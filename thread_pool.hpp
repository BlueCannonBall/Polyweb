#ifndef THREAD_POOL_HPP_
#define THREAD_POOL_HPP_

#include <chrono>
#include <condition_variable>
#include <exception>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace tp {
    enum TaskStatus {
        TASK_STATUS_RUNNING,
        TASK_STATUS_SUCCESS,
        TASK_STATUS_FAILURE,
    };

    class Task {
    protected:
        class BasicFunction {
        public:
            virtual ~BasicFunction() = default;

            virtual void call() = 0;
        };

        template <typename F>
        class Function : public BasicFunction {
        protected:
            F func;

        public:
            Function(F&& func):
                func(std::move(func)) {}

            void call() override {
                func();
            }
        };

        mutable std::mutex mutex;
        mutable std::condition_variable cv;
        std::unique_ptr<BasicFunction> func;
        TaskStatus status = TASK_STATUS_RUNNING;
        std::exception_ptr exception_ptr;

    public:
        template <typename F>
        Task(F&& func):
            func(std::make_unique<Function<std::decay_t<F>>>(std::forward<F>(func))) {}

        void execute() {
            try {
                func->call();

                std::lock_guard<std::mutex> lock(mutex);
                status = TASK_STATUS_SUCCESS;
            } catch (...) {
                std::lock_guard<std::mutex> lock(mutex);
                status = TASK_STATUS_FAILURE;
                exception_ptr = std::current_exception();
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

        std::exception_ptr get_exception_ptr() const {
            std::lock_guard<std::mutex> lock(mutex);
            return exception_ptr;
        }
    };

    class TaskManager {
    protected:
        std::mutex mutex;
        std::vector<std::weak_ptr<Task>> tasks;
        size_t gc_threshold = 64;

    public:
        ~TaskManager() {
            for (const auto& weak_task : tasks) {
                if (auto task = weak_task.lock()) {
                    task->wait();
                }
            }
        }

        void insert(std::weak_ptr<Task> task) {
            std::lock_guard<std::mutex> lock(mutex);
            tasks.push_back(std::move(task));
            if (tasks.size() >= gc_threshold) {
                tasks.erase(std::remove_if(tasks.begin(), tasks.end(), [](const auto& weak_task) {
                    auto task = weak_task.lock();
                    return !task || task->get_status() != TASK_STATUS_RUNNING;
                }),
                    tasks.end());
                gc_threshold = std::max<size_t>(64, tasks.size() * 2);
            }
        }
    };

    class ThreadPool {
    protected:
        class ControlBlock {
        public:
            std::mutex mutex;
            std::condition_variable cv;
            std::queue<std::shared_ptr<Task>> queue;
            unsigned int thread_count = 0;
            unsigned int target_thread_count = 0;
            unsigned int busy_thread_count = 0;

            ControlBlock() = default;
            ControlBlock(unsigned int target_thread_count = std::thread::hardware_concurrency()):
                target_thread_count(target_thread_count) {}
        };

        std::shared_ptr<ControlBlock> control_block;

        static void worker(std::shared_ptr<ControlBlock> control_block) {
            std::unique_lock<std::mutex> lock(control_block->mutex);
            while (control_block->target_thread_count >= control_block->thread_count) {
                control_block->cv.wait(lock, [&control_block] {
                    return !control_block->queue.empty() || control_block->target_thread_count < control_block->thread_count;
                });

                while (!control_block->queue.empty()) {
                    std::shared_ptr<Task> task = std::move(control_block->queue.front());
                    control_block->queue.pop();

                    ++control_block->busy_thread_count;
                    lock.unlock();
                    task->execute();
                    lock.lock();
                    --control_block->busy_thread_count;
                }
            }
            --control_block->thread_count;
            lock.unlock();
            control_block->cv.notify_all();
        }

    public:
        ThreadPool(unsigned int size = std::thread::hardware_concurrency()):
            control_block(std::make_shared<ControlBlock>(size)) {
            std::lock_guard<std::mutex> lock(control_block->mutex);
            for (; control_block->thread_count < control_block->target_thread_count; ++control_block->thread_count) {
                std::thread(&ThreadPool::worker, control_block).detach();
            }
        }
        ThreadPool(const ThreadPool&) = delete;
        ThreadPool(ThreadPool&&) = delete;

        ThreadPool& operator=(const ThreadPool&) = delete;
        ThreadPool& operator=(ThreadPool&&) = delete;

        ~ThreadPool() {
            std::unique_lock<std::mutex> lock(control_block->mutex);
            control_block->target_thread_count = 0;
            control_block->cv.notify_all();
            control_block->cv.wait(lock, [this]() {
                return !control_block->thread_count;
            });
        }

        template <typename F>
        std::shared_ptr<Task> schedule(F&& func, bool launch_if_busy = false) {
            auto task = std::make_shared<Task>(std::forward<F>(func));
            std::unique_lock<std::mutex> lock(control_block->mutex);
            if (launch_if_busy && control_block->busy_thread_count >= control_block->thread_count) {
                lock.unlock();
                std::thread([](std::shared_ptr<Task> task) {
                    task->execute();
                },
                    task)
                    .detach();
            } else {
                control_block->queue.push(task);
                lock.unlock();
                control_block->cv.notify_one();
            }
            return task;
        }

        unsigned int size() const {
            std::lock_guard<std::mutex> lock(control_block->mutex);
            return control_block->target_thread_count;
        }

        void resize(unsigned int size) {
            std::unique_lock<std::mutex> lock(control_block->mutex);
            control_block->target_thread_count = size;
            if (control_block->thread_count > control_block->target_thread_count) {
                lock.unlock();
                control_block->cv.notify_all();
            } else {
                for (; control_block->thread_count < control_block->target_thread_count; ++control_block->thread_count) {
                    std::thread(&ThreadPool::worker, control_block).detach();
                }
            }
        }
    };
} // namespace tp

#endif
