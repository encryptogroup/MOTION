#include <iostream>
#include <memory>
#include <random>

#include <fmt/format.h>

#include "base/party.h"
#include "wire/boolean_gmw_wire.h"

using namespace ABYN;

constexpr std::uint16_t PORT_OFFSET = 7777;

void test() {
  std::random_device rd("/dev/urandom");
  for (auto i = 0ull; i < 1u; ++i) {
    constexpr auto num_parties = 4u;
    std::srand(time(nullptr));
    std::size_t input_owner = std::rand() % num_parties, output_owner = std::rand() % num_parties;
    std::cout << fmt::format("Input owner: {}, output owner: {}\n", input_owner, output_owner);
    try {
      std::vector<PartyPtr> abyn_parties(0);
      std::vector<std::future<PartyPtr>> futures(0);

      // Party #0
      futures.push_back(std::async(std::launch::async, []() {
        std::vector<Communication::ContextPtr> parties;
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET,
                                                                      ABYN::Role::Server, 1));
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 1,
                                                                      ABYN::Role::Server, 2));
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 2,
                                                                      ABYN::Role::Server, 3));
        auto abyn = std::move(PartyPtr(new Party{parties, 0}));
        abyn->Connect();
        return std::move(abyn);
      }));

      // Party #1
      futures.push_back(std::async(std::launch::async, []() {
        std::string ip = "127.0.0.1";
        std::vector<Communication::ContextPtr> parties;
        parties.emplace_back(
            std::make_shared<Communication::Context>(ip, PORT_OFFSET, ABYN::Role::Client, 0));
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 3,
                                                                      ABYN::Role::Server, 2));
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 4,
                                                                      ABYN::Role::Server, 3));
        auto abyn = std::move(std::make_unique<Party>(parties, 1));
        abyn->Connect();
        return std::move(abyn);
      }));

      // Party #2
      futures.push_back(std::async(std::launch::async, []() {
        std::string ip = "127.0.0.1";
        std::uint16_t port = PORT_OFFSET + 1;
        auto abyn = std::move(PartyPtr(new Party{
            {std::make_shared<Communication::Context>(ip, port, ABYN::Role::Client, 0),
             std::make_shared<Communication::Context>(ip, PORT_OFFSET + 3, ABYN::Role::Client, 1),
             std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 5,
                                                      ABYN::Role::Server, 3)},
            2}));
        abyn->Connect();
        return std::move(abyn);
      }));

      // Party #3
      futures.push_back(std::async(std::launch::async, []() {
        auto abyn =
            std::move(PartyPtr(new Party{{std::make_shared<Communication::Context>(
                                              "127.0.0.1", PORT_OFFSET + 2, ABYN::Role::Client, 0),
                                          std::make_shared<Communication::Context>(
                                              "127.0.0.1", PORT_OFFSET + 4, ABYN::Role::Client, 1),
                                          std::make_shared<Communication::Context>(
                                              "127.0.0.1", PORT_OFFSET + 5, ABYN::Role::Client, 2)},
                                         3}));
        abyn->Connect();
        return std::move(abyn);
      }));

      for (auto &f : futures) abyn_parties.push_back(f.get());

      std::uniform_int_distribution<std::uint64_t> dist(0, 1);

      const std::size_t output_owner = std::rand() % num_parties;
      std::vector<bool> global_input_1(num_parties);
      for (auto j = 0ull; j < global_input_1.size(); ++j) {
        global_input_1.at(j) = (std::rand() % 2) == 1;
      }
      std::vector<ENCRYPTO::BitVector<>> global_input_1K(num_parties), global_input_100K(num_parties);
      for (auto j = 0ull; j < global_input_1K.size(); ++j) {
        global_input_1K.at(j) = ENCRYPTO::BitVector<>::Random(1000);
        global_input_100K.at(j) = ENCRYPTO::BitVector<>::Random(100000);
      }
      bool dummy_input_1 = false;
      ENCRYPTO::BitVector dummy_input_1K(1000, false);
      ENCRYPTO::BitVector dummy_input_100K(100000, false);

      // std::vector<PartyPtr> abyn_parties(std::move(Party::GetNLocalParties(num_parties, 7777)));
      std::vector<std::thread> threads;
      //#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
      //#pragma omp single
      //#pragma omp taskloop num_tasks(abyn_parties.size())
      for (auto &party : abyn_parties) {
        threads.emplace_back([&]() {
          const auto BGMW = MPCProtocol::BooleanGMW;
          std::vector<Shares::SharePtr> input_share_1, input_share_1K, input_share_100K;
          auto _100K_vector_size = 1000;
          std::vector<std::vector<Shares::SharePtr>> input_share_100K_vector(_100K_vector_size);
          std::vector<Shares::SharePtr> output_share_100K_vector(_100K_vector_size);

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == party->GetConfiguration()->GetMyId()) {
              input_share_1.push_back(party->IN<BGMW>(static_cast<bool>(global_input_1.at(j)), j));
              input_share_1K.push_back(party->IN<BGMW>(global_input_1K.at(j), j));
              input_share_100K.push_back(party->IN<BGMW>(global_input_100K.at(j), j));
            } else {
              input_share_1.push_back(party->IN<BGMW>(dummy_input_1, j));
              input_share_1K.push_back(party->IN<BGMW>(dummy_input_1K, j));
              input_share_100K.push_back(party->IN<BGMW>(dummy_input_100K, j));
            }
          }

          auto xor_1 = party->XOR(input_share_1.at(0), input_share_1.at(1));
          auto xor_1K = party->XOR(input_share_1K.at(0), input_share_1K.at(1));
          auto xor_100K = party->XOR(input_share_100K.at(0), input_share_100K.at(1));

          for (auto j = 2ull; j < num_parties; ++j) {
            xor_1 = party->XOR(xor_1, input_share_1.at(j));
            xor_1K = party->XOR(xor_1K, input_share_1K.at(j));
            xor_100K = party->XOR(xor_100K, input_share_100K.at(j));
          }

          auto output_share_1 = party->OUT(xor_1, output_owner);
          auto output_share_1K = party->OUT(xor_1K, output_owner);
          auto output_share_100K = party->OUT(xor_100K, output_owner);

          for (auto k = 0ull; k < input_share_100K_vector.size(); ++k) {
            for (auto j = 0ull; j < num_parties; ++j) {
              if (j == party->GetConfiguration()->GetMyId()) {
                input_share_100K_vector.at(k).push_back(party->IN<BGMW>(global_input_100K.at(j), j));
              } else {
                input_share_100K_vector.at(k).push_back(party->IN<BGMW>(dummy_input_100K, j));
              }
            }

            auto xor_100Kv =
                party->XOR(input_share_100K_vector.at(k).at(0), input_share_100K_vector.at(k).at(1));

            for (auto j = 2ull; j < num_parties; ++j) {
              xor_100Kv = party->XOR(xor_100Kv, input_share_100K_vector.at(k).at(j));
            }

            output_share_100K_vector.at(k) = party->OUT(xor_100Kv, output_owner);
          }

          party->Run();

          if (party->GetConfiguration()->GetMyId() == output_owner) {
            auto wire_1 =
                std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_share_1->GetWires().at(0));
            auto wire_1K =
                std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_share_1K->GetWires().at(0));
            auto wire_100K =
                std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_share_100K->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);
            assert(wire_100K);

            assert(wire_1->GetValuesOnWire().Get(0) == Helpers::XORReduceBitVector(global_input_1));
            assert(wire_1K->GetValuesOnWire() == Helpers::XORBitVectors(global_input_1K));
            assert(wire_100K->GetValuesOnWire() == Helpers::XORBitVectors(global_input_100K));

            for (auto &s : output_share_100K_vector) {
              auto wire_100K_v =
                  std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(s->GetWires().at(0));

              assert(wire_100K_v);

              assert(wire_100K_v->GetValuesOnWire() == Helpers::XORBitVectors(global_input_100K));
            }
          }

          party->Finish();
        });
      }
      for (auto &t : threads) {
        t.join();
      }
    } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
    }
  }
  std::cout << "Finished\n";
}

int main() {
  test();
  return 0;
}
