#ifndef THREADPOOL_HPP_
#define THREADPOOL_HPP_

#include <chrono>
#include <condition_variable>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>

namespace tp {
    enum TaskStatus {
        TASK_STATUS_RUNNING,
        TASK_STATUS_SUCCESS,
        TASK_STATUS_FAILURE,
    };

    class Task {
    protected:
        mutable std::mutex mutex;
        mutable std::condition_variable cv;

    public:
        std::function<void(void*)> func;
        void* arg = nullptr;
        TaskStatus status = TASK_STATUS_RUNNING;
        std::exception_ptr error;

        Task(std::function<void(void*)> func, void* arg = nullptr):
            func(std::move(func)),
            arg(arg) {}

        void execute() {
            try {
                func(arg);

                std::lock_guard<std::mutex> lock(mutex);
                status = TASK_STATUS_SUCCESS;
            } catch (...) {
                std::lock_guard<std::mutex> lock(mutex);
                status = TASK_STATUS_FAILURE;
                error = std::current_exception();
            }
            cv.notify_all();
        }

        TaskStatus wait() const {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [this]() {
                return status != TASK_STATUS_RUNNING;
            });
            return status;
        }

        template <typename Rep, typename Period>
        TaskStatus wait_for(const std::chrono::duration<Rep, Period>& time) const {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait_for(lock, time, [this]() {
                return status != TASK_STATUS_RUNNING;
            });
            return status;
        }

        template <typename Clock, typename Duration>
        TaskStatus wait_until(const std::chrono::time_point<Clock, Duration>& time) const {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait_until(lock, time, [this]() {
                return status != TASK_STATUS_RUNNING;
            });
            return status;
        }

        TaskStatus get_status() const {
            std::lock_guard<std::mutex> lock(mutex);
            return status;
        }

        std::exception_ptr get_error() const {
            std::lock_guard<std::mutex> lock(mutex);
            return error;
        }
    };

    namespace detail {
        class ControlBlock {
        public:
            std::mutex mutex;
            std::condition_variable cv;
            std::queue<std::shared_ptr<Task>> queue;
            unsigned int thread_count = 0;
            unsigned int target_thread_count;
            unsigned int busy_count = 0;

            ControlBlock(unsigned int size = std::thread::hardware_concurrency()):
                target_thread_count(size) {}
        };
    } // namespace detail

    class ThreadPool {
    protected:
        std::shared_ptr<detail::ControlBlock> control_block;

        static void runner(std::shared_ptr<detail::ControlBlock> control_block) {
            std::unique_lock<std::mutex> lock(control_block->mutex);
            ++control_block->thread_count;
            control_block->cv.notify_all();

            for (;; control_block->cv.wait(lock)) {
                while (!control_block->queue.empty()) {
                    std::shared_ptr<Task> task = std::move(control_block->queue.front());
                    control_block->queue.pop();

                    ++control_block->busy_count;
                    lock.unlock();
                    task->execute();
                    lock.lock();
                    --control_block->busy_count;
                }
                if (control_block->target_thread_count < control_block->thread_count) {
                    break;
                }
            }

            --control_block->thread_count;
            control_block->cv.notify_all();
        }

    public:
        ThreadPool(unsigned int size = std::thread::hardware_concurrency()):
            control_block(std::make_shared<detail::ControlBlock>(size)) {
            for (unsigned int i = 0; i < control_block->target_thread_count; ++i) {
                std::thread(&ThreadPool::runner, control_block).detach();
            }

            std::unique_lock<std::mutex> lock(control_block->mutex);
            control_block->cv.wait(lock, [this]() {
                return control_block->thread_count == control_block->target_thread_count;
            });
        }
        ThreadPool(const ThreadPool&) = delete;

        ThreadPool& operator=(const ThreadPool&) = delete;

        ~ThreadPool() {
            std::unique_lock<std::mutex> lock(control_block->mutex);
            control_block->target_thread_count = 0;
            control_block->cv.notify_all();
            control_block->cv.wait(lock, [this]() {
                return !control_block->thread_count;
            });
        }

        std::shared_ptr<Task> schedule(std::function<void(void*)> func, void* arg = nullptr, bool launch_if_busy = false) {
            std::shared_ptr<Task> task = std::make_shared<Task>(std::move(func), arg);

            if (launch_if_busy) {
                std::unique_lock<std::mutex> lock(control_block->mutex);
                if (control_block->busy_count >= control_block->thread_count) {
                    lock.unlock();
                    std::thread(&Task::execute, task).detach();
                    return task;
                }
            }

            std::unique_lock<std::mutex> lock(control_block->mutex);
            control_block->queue.push(task);
            lock.unlock();
            control_block->cv.notify_one();
            return task;
        }

        void resize(unsigned int size) {
            std::unique_lock<std::mutex> lock(control_block->mutex);

            if (size < control_block->target_thread_count) {
                control_block->target_thread_count = size;
                control_block->cv.notify_all();
            } else if (size > control_block->target_thread_count) {
                for (unsigned int i = 0; i < size - control_block->target_thread_count; ++i) {
                    std::thread(&ThreadPool::runner, control_block).detach();
                }
                control_block->target_thread_count = size;
            } else {
                return;
            }

            control_block->cv.wait(lock, [this]() {
                return control_block->thread_count == control_block->target_thread_count;
            });
        }

        unsigned int size() const {
            std::lock_guard<std::mutex> lock(control_block->mutex);
            return control_block->target_thread_count;
        }
    };
} // namespace tp

#endif
