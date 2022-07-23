#include "garbled_circuit_message.h"

#include "fbs_headers/garbled_circuit_message_generated.h"
#include "message.h"

namespace encrypto::motion::communication {

// publish input owner's masked inputs
flatbuffers::FlatBufferBuilder BuildGarbledCircuitSetupMessage(
    std::span<const std::byte> aes_key_data, std::span<const std::byte> hash_key_data) {
  flatbuffers::FlatBufferBuilder fbb(50);
  auto aes_key{fbb.CreateVector<std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(aes_key_data.data()), aes_key_data.size())};
  auto hash_key{fbb.CreateVector<std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(hash_key_data.data()), hash_key_data.size())};
  auto setup_message_root{
      encrypto::motion::communication::CreateGarbledCircuitSetupMessage(fbb, aes_key, hash_key)};
  fbb.Finish(setup_message_root);
  return BuildMessage(MessageType::kGarbledCircuitSetup, 0,
                      std::span(fbb.GetBufferPointer(), fbb.GetSize()));
}

}  // namespace encrypto::motion::communication
