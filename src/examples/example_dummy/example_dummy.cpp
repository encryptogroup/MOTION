#include <iostream>
#include <memory>
#include <random>

#include <fmt/format.h>

#include "base/party.h"

using namespace ABYN;

constexpr std::uint16_t PORT_OFFSET = 7777;

void test() {
  std::vector<std::size_t> sizes;
  for (auto i = 1; i < 20; ++i) {
    sizes.push_back(i);
  }
  for (auto i = 128ull; i <= 100000; i *= 2) {
    sizes.push_back(i);
  }
  for (auto size : sizes) {
    std::random_device rd("/dev/urandom");
    std::uniform_int_distribution<uint64_t> dist_n_vectors(2, 20);

    std::vector<std::vector<bool>> stl_vectors(dist_n_vectors(rd));
    std::vector<ENCRYPTO::BitVector> bit_vectors(stl_vectors.size());

    std::uniform_int_distribution<uint64_t> dist(0, 1);

    for(auto j = 0ull; j < stl_vectors.size(); ++j) {
      for (auto i = 0ull; i < size; ++i) {
        stl_vectors.at(j).push_back(dist(rd));
        bit_vectors.at(j).Append(stl_vectors.at(j).at(i));
        assert(stl_vectors.at(j).at(i) == bit_vectors.at(j).Get(i));
      }
    }

    std::vector<bool> stl_vector_result, bit_vector_result_as_stl;
    ENCRYPTO::BitVector bit_vector_result;

    for(auto i = 0ull; i < stl_vectors.size(); ++i) {
      stl_vector_result.insert(stl_vector_result.end(), stl_vectors.at(i).begin(), stl_vectors.at(i).end());
      bit_vector_result.Append(bit_vectors.at(i));
    }

    for (auto i = 0ull; i < stl_vector_result.size(); ++i) {
      bit_vector_result_as_stl.push_back(bit_vector_result.Get(i));
    }

    for (auto i = 0ull; i < stl_vector_result.size(); ++i) {
      assert(stl_vector_result.at(i) == bit_vector_result_as_stl.at(i));
    }
    std::cout << "*\n";
  }

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
          std::vector<CommunicationContextPtr> parties;
          parties.emplace_back(std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET,
                                                                      ABYN::Role::Server, 1));
          parties.emplace_back(std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET + 1,
                                                                      ABYN::Role::Server, 2));
          parties.emplace_back(std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET + 2,
                                                                      ABYN::Role::Server, 3));
          auto abyn = std::move(PartyPtr(new Party{parties, 0}));
          abyn->Connect();
          return std::move(abyn);
        }));

        // Party #1
        futures.push_back(std::async(std::launch::async, []() {
          std::string ip = "127.0.0.1";
          std::vector<CommunicationContextPtr> parties;
          parties.emplace_back(
              std::make_shared<CommunicationContext>(ip, PORT_OFFSET, ABYN::Role::Client, 0));
          parties.emplace_back(std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET + 3,
                                                                      ABYN::Role::Server, 2));
          parties.emplace_back(std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET + 4,
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
              {std::make_shared<CommunicationContext>(ip, port, ABYN::Role::Client, 0),
               std::make_shared<CommunicationContext>(ip, PORT_OFFSET + 3, ABYN::Role::Client, 1),
               std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET + 5,
                                                      ABYN::Role::Server, 3)},
              2}));
          abyn->Connect();
          return std::move(abyn);
        }));

        // Party #3
        futures.push_back(std::async(std::launch::async, []() {
          auto abyn =
              std::move(PartyPtr(new Party{{std::make_shared<CommunicationContext>(
                  "127.0.0.1", PORT_OFFSET + 2, ABYN::Role::Client, 0),
                                            std::make_shared<CommunicationContext>(
                                                "127.0.0.1", PORT_OFFSET + 4, ABYN::Role::Client, 1),
                                            std::make_shared<CommunicationContext>(
                                                "127.0.0.1", PORT_OFFSET + 5, ABYN::Role::Client, 2)},
                                           3}));
          abyn->Connect();
          return std::move(abyn);
        }));

        for (auto &f : futures) abyn_parties.push_back(f.get());


      //std::vector<PartyPtr> abyn_parties(std::move(Party::GetNLocalParties(num_parties, 7777)));
      std::vector<std::thread> threads;
      //#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
      //#pragma omp single
      //#pragma omp taskloop num_tasks(abyn_parties.size())
      for (auto &party : abyn_parties) {
        threads.emplace_back([&]() {
          bool in[4] = {true, true, true, false};
          /*auto s_in_0 = party->IN<Protocol::BooleanGMW>(0, in[0]);
          auto s_in_1 = party->IN<Protocol::BooleanGMW>(1, in[1]);
          auto s_in_2 = party->IN<Protocol::BooleanGMW>(2, in[2]);
          auto s_in_3 = party->IN<Protocol::BooleanGMW>(3, in[3]);*/

          auto s_in_0 = party->IN<Protocol::ArithmeticGMW, std::uint8_t>(0, in[0]);
          auto s_in_1 = party->IN<Protocol::ArithmeticGMW, std::uint8_t>(1, in[1]);
          auto s_in_2 = party->IN<Protocol::ArithmeticGMW, std::uint8_t>(2, in[2]);
          //auto s_in_3 = party->IN<Protocol::ArithmeticGMW, std::uint8_t>(3, in[3]);



          // auto added_share = abyn_parties.at(party_id)->IN<Protocol::BooleanGMW>(s_in_0, s_in_1);
          // // s_add = s_in_0 + s_in_1 added_share = abyn_parties.at(party_id)->ADD(added_share,
          // s_in_2);
          // // s_add += s_in_2 added_share = abyn_parties.at(party_id)->ADD(added_share, s_in_3);
          // // s_add += s_in_3

          // auto output_share = abyn_parties.at(party_id)->OUT(added_share, output_owner);

          party->Run();

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
