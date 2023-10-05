#ifndef _THREADPOOL_HPP
#define _THREADPOOL_HPP

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace tp {
    enum TaskStatus {
        TASK_STATUS_RUNNING,
        TASK_STATUS_SUCCESS,
        TASK_STATUS_FAILURE,
    };

    class Task {
    protected:
        std::mutex mutex;
        std::condition_variable cv;

    public:
        TaskStatus status = TASK_STATUS_RUNNING;
        std::function<void(void*)> func;
        void* arg = nullptr;
        std::exception error;

        Task(std::function<void(void*)> func, void* arg = nullptr):
            func(std::move(func)),
            arg(arg) {}

        void execute() {
            mutex.lock();
            try {
                func(arg);
                status = TASK_STATUS_SUCCESS;
            } catch (const std::exception& e) {
                error = e;
                status = TASK_STATUS_FAILURE;
            }
            mutex.unlock();
            cv.notify_all();
        }

        TaskStatus await() {
            std::unique_lock<std::mutex> lock(mutex);
            while (status == TASK_STATUS_RUNNING) {
                cv.wait(lock);
            }
            return status;
        }
    };

    class ThreadPool {
    protected:
        void runner() {
            std::unique_lock<std::mutex> lock(mutex);
            for (; target_thread_count >= thread_count; cv.wait(lock)) {
                while (!queue.empty()) {
                    std::shared_ptr<Task> task = std::move(queue.front());
                    queue.pop();

                    lock.unlock();
                    task->execute();
                    lock.lock();

                    --busy_count;
                }
            }
            --thread_count;
            lock.unlock();
            cv.notify_all();
        }

        std::mutex mutex;
        std::condition_variable cv;
        std::queue<std::shared_ptr<Task>> queue;
        unsigned int thread_count;
        unsigned int target_thread_count;
        unsigned int busy_count;

    public:
        ThreadPool(unsigned int size = std::thread::hardware_concurrency()):
            thread_count(0),
            target_thread_count(size),
            busy_count(0) {
            for (unsigned int i = 0; i < target_thread_count; ++i) {
                std::thread(&ThreadPool::runner, this).detach();
            }
        }

        ~ThreadPool() {
            std::unique_lock<std::mutex> lock(mutex);
            target_thread_count = 0;
            lock.unlock();
            cv.notify_all();
            lock.lock();
            while (thread_count) {
                cv.wait(lock);
            }
        }

        std::shared_ptr<Task> schedule(std::function<void(void*)> func, void* arg = nullptr, bool launch_if_busy = false) {
            std::shared_ptr<Task> task = std::make_shared<Task>(std::move(func), arg);

            if (launch_if_busy) {
                std::unique_lock<std::mutex> lock(mutex);
                if (busy_count >= target_thread_count) {
                    lock.unlock();
                    std::thread(&Task::execute, task).detach();
                    return task;
                }
            }

            mutex.lock();
            queue.push(task);
            ++busy_count;
            mutex.unlock();
            cv.notify_one();
            return task;
        };

        void resize(unsigned int size) {
            std::unique_lock<std::mutex> lock(mutex);
            if (size < target_thread_count) {
                target_thread_count = size;
                lock.unlock();
                cv.notify_all();
            } else if (size > target_thread_count) {
                target_thread_count = size;
                for (; thread_count < target_thread_count; ++thread_count) {
                    std::thread(&ThreadPool::runner, this).detach();
                }
            }
        }

        unsigned int size() const {
            return target_thread_count;
        }
    };
} // namespace tp

#endif
