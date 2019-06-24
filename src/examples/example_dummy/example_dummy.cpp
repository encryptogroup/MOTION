#include <iostream>
#include <memory>
#include <random>

#include <fmt/format.h>

#include "base/party.h"

using namespace ABYN;

constexpr std::uint16_t PORT_OFFSET = 7777;

void test() {
  for (auto i = 0ull; i < 2000; ++i) {
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
        auto abyn = std::move(PartyPtr(new Party{parties, 1}));
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

      // std::vector<PartyPtr> abyn_parties(std::move(Party::GetNLocalParties(num_parties, 7777)));
      std::vector<std::thread> threads;
      //#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
      //#pragma omp single
      //#pragma omp taskloop num_tasks(abyn_parties.size())
      for (auto &party : abyn_parties) {
        threads.emplace_back([&]() {
          bool in[4] = {true, true, true, false};
          bool out[4] = {false, false, false, false};
          Shares::SharePtr s_in[4], s_out[4];

          for (auto i = 0ull; i < 4u; ++i) {
            s_in[i] = party->IN<Protocol::BooleanGMW>(in[i], i);
            s_out[i] = party->OUT(s_in[i], i);
          }
          // auto added_share = abyn_parties.at(party_id)->IN<Protocol::BooleanGMW>(s_in_0, s_in_1);
          // // s_add = s_in_0 + s_in_1 added_share = abyn_parties.at(party_id)->ADD(added_share,
          // s_in_2);
          // // s_add += s_in_2 added_share = abyn_parties.at(party_id)->ADD(added_share, s_in_3);
          // // s_add += s_in_3

          // auto output_share = abyn_parties.at(party_id)->OUT(added_share, output_owner);

          party->Run();

          for (auto i = 0ull; i < 4u; ++i) {
            auto wire = std::dynamic_pointer_cast<Wires::GMWWire>(s_out[i]->GetWires().at(0));
            assert(wire);
            out[i] = wire->GetValuesOnWire().Get(0);
          }

          auto tmp_in = in[party->GetConfiguration()->GetMyId()];
          auto tmp_out = out[party->GetConfiguration()->GetMyId()];

          assert(tmp_in == tmp_out);

          /* if (party_id == output_owner) {
             auto wire = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
                 output_share->GetWires().at(0));
             T circuit_result = wire->GetValuesOnWire().at(0);
             T expected_result = inputs.at(0) + inputs.at(1) + inputs.at(2) + inputs.at(3);
             std::cout << "Circuit result : " << unsigned(circuit_result) <<
                       " \t Expected result: " << unsigned(expected_result) << "\n";
             assert(circuit_result == expected_result);
           }*/
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
