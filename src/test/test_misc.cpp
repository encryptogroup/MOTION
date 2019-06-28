#include <future>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "test_constants.h"
#include "utility/condition.h"

namespace {
TEST(Condition, Wait_NotifyOne) {
    int i = 0;
    ENCRYPTO::Condition condition([&i]() { return i == 1; });

    std::future<bool> wait_0 =
        std::async(std::launch::async, [&condition]() { return condition.Wait(); });
    std::future<bool> wait_1 =
        std::async(std::launch::async, [&condition]() { return condition.Wait(); });
    std::future<bool> wait_2 =
        std::async(std::launch::async, [&condition]() { return condition.Wait(); });

    {
      std::scoped_lock<std::mutex>(condition.GetMutex());
      i = 1;
    }

    condition.NotifyOne();
    condition.NotifyOne();
    condition.NotifyOne();

    wait_0.wait();
    ASSERT_TRUE(wait_0.get());

    wait_1.wait();
    ASSERT_TRUE(wait_1.get());

    wait_2.wait();
    ASSERT_TRUE(wait_2.get());
}

TEST(Condition, Wait_NotifyAll) {
    int i = 0;
    ENCRYPTO::Condition condition([&i]() { return i == 1; });

    std::future<bool> wait_0 =
        std::async(std::launch::async, [&condition]() { return condition.Wait(); });
    std::future<bool> wait_1 =
        std::async(std::launch::async, [&condition]() { return condition.Wait(); });
    std::future<bool> wait_2 =
        std::async(std::launch::async, [&condition]() { return condition.Wait(); });

    {
      std::scoped_lock<std::mutex>(condition.GetMutex());
      i = 1;
    }

    condition.NotifyAll();

    wait_0.wait();
    ASSERT_TRUE(wait_0.get());

    wait_1.wait();
    ASSERT_TRUE(wait_1.get());

    wait_2.wait();
    ASSERT_TRUE(wait_2.get());
}

TEST(Condition, WaitForTrue) {
    int i = 0;
    ENCRYPTO::Condition condition([&i]() { return i == 1; });

    std::future<bool> wait_0 =
        std::async(std::launch::async, [&condition]() { return condition.Wait(); });
    std::future<bool> wait_1 =
        std::async(std::launch::async, [&condition]() { return condition.Wait(); });
    std::future<bool> wait_2 =
        std::async(std::launch::async, [&condition]() { return condition.Wait(); });

    {
      std::scoped_lock<std::mutex>(condition.GetMutex());
      i = 1;
    }

    condition.NotifyAll();

    wait_0.wait();
    ASSERT_TRUE(wait_0.get());

    wait_1.wait();
    ASSERT_TRUE(wait_1.get());

    wait_2.wait();
    ASSERT_TRUE(wait_2.get());
}

TEST(Condition, WaitForFalse) {
    int i = 0;
    ENCRYPTO::Condition condition([&i]() { return i == 1; });

    std::future<bool> wait_0 = std::async(std::launch::async, [&condition]() {
      return condition.WaitFor(std::chrono::microseconds(1));
    });

    condition.NotifyOne();

    std::this_thread::sleep_for(std::chrono::microseconds(10));

    wait_0.wait();
    ASSERT_FALSE(wait_0.get());

    {
      std::scoped_lock<std::mutex>(condition.GetMutex());
      i = 1;
    }

    std::future<bool> wait_1 = std::async(std::launch::async, [&condition]() {
      return condition.WaitFor(std::chrono::seconds(100));
    });

    std::future<bool> wait_2 = std::async(std::launch::async, [&condition]() {
      return condition.WaitFor(std::chrono::seconds(100));
    });

    condition.NotifyAll();

    wait_1.wait();
    ASSERT_TRUE(wait_1.get());

    wait_2.wait();
    ASSERT_TRUE(wait_2.get());
}

TEST(Condition, WaitForComplexFunction) {
    struct {
      std::vector<int> v{0, 1, 2};
      auto GetCondition() {
        return ENCRYPTO::Condition([this]() { return v.size() == 1; });
      }
    } tmp_struct;

    auto condition = tmp_struct.GetCondition();

    std::future<bool> wait_0 = std::async(std::launch::async, [&condition]() {
      return condition.WaitFor(std::chrono::microseconds(1));
    });

    {
      std::scoped_lock<std::mutex>(condition.GetMutex());
      tmp_struct.v.erase(tmp_struct.v.end() - 1);
    }

    condition.NotifyOne();

    std::this_thread::sleep_for(std::chrono::microseconds(10));

    wait_0.wait();
    ASSERT_FALSE(wait_0.get());

    {
      std::scoped_lock<std::mutex>(condition.GetMutex());
      tmp_struct.v.erase(tmp_struct.v.end() - 1);
    }

    std::future<bool> wait_1 = std::async(std::launch::async, [&condition]() {
      return condition.WaitFor(std::chrono::seconds(100));
    });
    std::future<bool> wait_2 = std::async(std::launch::async, [&condition]() {
      return condition.WaitFor(std::chrono::seconds(100));
    });

    condition.NotifyAll();

    wait_1.wait();
    ASSERT_TRUE(wait_1.get());

    wait_2.wait();
    ASSERT_TRUE(wait_2.get());
}
}