#include "../polyweb.hpp"
#include <assert.h>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <stddef.h>
#include <stdlib.h>
#include <vector>

using nlohmann::json;

int main() {
    pn::init();

    pw::HTTPResponse resp;
    if (pw::fetch("https://hacker-news.firebaseio.com/v0/topstories.json", resp) == PN_ERROR) {
        std::cerr << "Error: " << pw::universal_strerror() << std::endl;
        return 1;
    }
    assert(resp.status_code == 200);
    json story_ids = json::parse(resp.body_string());
    assert(story_ids.is_array() && story_ids.size() >= 10);

    std::cout << "10 stories on Hacker News today:" << std::endl;
    std::vector<std::shared_ptr<tp::Task>> tasks;
    for (size_t i = 0; i < 10; ++i) {
        tasks.push_back(pw::thread_pool.schedule([&story_ids, i](void*) {
            pw::HTTPResponse resp;
            if (pw::fetch("https://hacker-news.firebaseio.com/v0/item/" + std::to_string(story_ids[i].get<int>()) + ".json", resp) == PN_ERROR) {
                std::cerr << "Error: " << pw::universal_strerror() << std::endl;
                exit(1);
            }
            assert(resp.status_code == 200);
            json story = json::parse(resp.body_string());

            std::cout << story["title"].get<std::string>() << std::endl;
        }));
    }
    for (const auto& task : tasks) {
        assert(task->wait() == tp::TASK_STATUS_SUCCESS);
    }

    pn::quit();
    return 0;
}
