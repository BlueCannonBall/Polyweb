#ifndef THREAD_POOL_HPP_
#define THREAD_POOL_HPP_

#include <chrono>
#include <condition_variable>
#include <exception>
#include <list>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <type_traits>

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
        TaskStatus status = TASK_STATUS_RUNNING;
        std::exception_ptr error;

        class BasicFunction {
        public:
            virtual ~BasicFunction() = default;

            virtual void call(void* arg) = 0;
        };

        template <typename F>
        class Function : public BasicFunction {
        protected:
            F func;

        public:
            Function(F&& func):
                func(std::move(func)) {}

            void call(void* arg) override {
                func(arg);
            }
        };

    public:
        std::unique_ptr<BasicFunction> func;
        void* arg = nullptr;

        template <typename F>
        Task(F&& func, void* arg = nullptr):
            func(std::make_unique<Function<std::decay_t<F>>>(std::forward<F>(func))),
            arg(arg) {}

        void execute() {
            try {
                func->call(arg);

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

    class TaskList {
    protected:
        std::list<std::weak_ptr<Task>> tasks;

    public:
        ~TaskList() {
            for (const auto& task : tasks) {
                if (auto task_locked = task.lock()) {
                    task_locked->wait();
                }
            }
        }

        void insert(std::weak_ptr<Task> task) {
            tasks.push_back(std::move(task));
            for (auto it = tasks.begin(); it != tasks.end();) {
                if (auto task_locked = it->lock(); !task_locked || task_locked->get_status() != TASK_STATUS_RUNNING) {
                    it = tasks.erase(it);
                } else {
                    ++it;
                }
            }
        }
    };

    namespace detail {
        class ControlBlock {
        public:
            std::mutex mutex;
            std::condition_variable cv;
            std::queue<std::shared_ptr<Task>> queue;
            unsigned int target_thread_count;
            unsigned int persistent_thread_count = 0;
            unsigned int busy_thread_count = 0;
            unsigned int total_thread_count = 0;

            ControlBlock(unsigned int target_thread_count = std::thread::hardware_concurrency()):
                target_thread_count(target_thread_count) {}
        };
    } // namespace detail

    class ThreadPool {
    protected:
        std::shared_ptr<detail::ControlBlock> control_block;

        static void runner(std::shared_ptr<detail::ControlBlock> control_block) {
            std::unique_lock<std::mutex> lock(control_block->mutex);
            ++control_block->persistent_thread_count;
            ++control_block->total_thread_count;
            control_block->cv.notify_all();

            for (;; control_block->cv.wait(lock)) {
                while (!control_block->queue.empty()) {
                    std::shared_ptr<Task> task = std::move(control_block->queue.front());
                    control_block->queue.pop();

                    ++control_block->busy_thread_count;
                    lock.unlock();
                    task->execute();
                    lock.lock();
                    --control_block->busy_thread_count;
                }
                if (control_block->target_thread_count < control_block->total_thread_count) {
                    break;
                }
            }

            --control_block->persistent_thread_count;
            --control_block->total_thread_count;
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
                return control_block->persistent_thread_count == control_block->target_thread_count;
            });
        }
        ThreadPool(const ThreadPool&) = delete;

        ThreadPool& operator=(const ThreadPool&) = delete;

        ~ThreadPool() {
            std::unique_lock<std::mutex> lock(control_block->mutex);
            control_block->target_thread_count = 0;
            control_block->cv.notify_all();
            control_block->cv.wait(lock, [this]() {
                return !control_block->total_thread_count;
            });
        }

        template <typename F>
        std::shared_ptr<Task> schedule(F&& func, void* arg = nullptr, bool launch_if_busy = false) {
            auto task = std::make_shared<Task>(std::forward<F>(func), arg);

            std::unique_lock<std::mutex> lock(control_block->mutex);
            if (launch_if_busy && control_block->busy_thread_count >= control_block->persistent_thread_count) {
                lock.unlock();
                std::thread([](std::shared_ptr<detail::ControlBlock> control_block, std::shared_ptr<Task> task) {
                    std::unique_lock<std::mutex> lock(control_block->mutex);
                    ++control_block->total_thread_count;
                    lock.unlock();
                    task->execute();
                    lock.lock();
                    --control_block->total_thread_count;
                    control_block->cv.notify_all();
                },
                    control_block,
                    task)
                    .detach();
            } else {
                control_block->queue.push(task);
                lock.unlock();
                control_block->cv.notify_one();
            }

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
                return control_block->persistent_thread_count == control_block->target_thread_count;
            });
        }

        unsigned int size() const {
            std::lock_guard<std::mutex> lock(control_block->mutex);
            return control_block->target_thread_count;
        }
    };
} // namespace tp

#endif
