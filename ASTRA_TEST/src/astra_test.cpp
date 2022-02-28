#include <iostream>
#include <random>
#include <limits>
#include <memory>
#include <cassert>
#include <array>

#define private public

constexpr std::size_t kAll = std::numeric_limits<std::size_t>::max();


//Simple randomness generation for testing purposes

constexpr std::size_t kKey_0_1 = 0;
constexpr std::size_t kKey_1_0 = 1;
constexpr std::size_t kKey_0_2 = 2;
constexpr std::size_t kKey_2_0 = 3;
constexpr std::size_t kKey_1_2 = 4;
constexpr std::size_t kKey_2_1 = 5;
constexpr std::size_t kKeyP_0 = 6;
constexpr std::size_t kKeyP_1 = 7;
constexpr std::size_t kKeyP_2 = 8;

uint64_t GetRandomValue(std::size_t key_id) {
    static std::mt19937_64 mt_64[9];
    static std::uniform_int_distribution<uint64_t> 
      ui(std::numeric_limits<std::size_t>::min(), std::numeric_limits<std::size_t>::max());
    return ui(mt_64[key_id]);
}


//simple send and receive functionality for testing purposes
uint64_t message_buffer[3];

void Send(std::size_t sender_id, std::size_t receiver_id, uint64_t message) {
    message_buffer[sender_id + receiver_id - 1] = message;
}

uint64_t Receive(std::size_t sender_id, std::size_t receiver_id) {
    return message_buffer[sender_id + receiver_id - 1];
}

//Simplified versions of motion wires
namespace encrypto::motion {
    
class Wire {
 public:
 
  Wire() = default;
  
  virtual ~Wire() = default;

  Wire(const Wire&) = delete;
};

using WirePointer = std::shared_ptr<motion::Wire>;

} // namespace encrypto::motion

//Simplified version of motion gates
namespace encrypto::motion {
    
class Gate {
 public:
  Gate() = default;
 
  virtual ~Gate() = default;

  virtual void EvaluateSetup() = 0;

  virtual void EvaluateOnline() = 0;

  const std::vector<WirePointer>& GetOutputWires() const { return output_wires_; }

 protected:
  std::size_t id_ = -1;
  std::vector<WirePointer> output_wires_;
};

class OneGate : public Gate {
 public:
  OneGate() = default;
 
  ~OneGate() override = default;

  OneGate(OneGate&) = delete;

 protected:
  std::vector<WirePointer> parent_;
};

class TwoGate : public Gate {
 public:
  TwoGate() = default;
  
  ~TwoGate() override = default;
  
  TwoGate(TwoGate&) = delete;
  
 protected:
  std::vector<WirePointer> parent_a_;
  std::vector<WirePointer> parent_b_;
};
    
class InputGate : public Gate {
 public:
  InputGate() = default;
  virtual ~InputGate() = default;
    
 protected:
  std::size_t input_owner_ = -1;
};

class OutputGate : public OneGate {
 public:
  OutputGate() = default;
  virtual ~OutputGate() = default;  
};

} // namespace encrypto::motion

namespace encrypto::motion::proto::astra {
    
template<typename T>
class Wire final : public motion::Wire {
 public:
 
 Wire() = default;
 
  Wire(const T& value, const T& lambda_x_0, const T& lambda_x_1)
  : value_{value}, lambda_x_i_{lambda_x_0, lambda_x_1} {}
  
  ~Wire() = default;
  
  T& GetMutableValue() { return value_; }
  std::array<T, 2>& GetMutableLambdas() { return lambda_x_i_; }
  
 private:
  T value_;
  std::array<T, 2> lambda_x_i_;
};

template<typename T>
using WirePointer = std::shared_ptr<astra::Wire<T>>;
    
} // namespace encrypto::motion::proto::astra

namespace encrypto::motion::proto::astra {

template <typename T>
class InputGate final : public motion::InputGate {
  using Base = motion::InputGate;

 public:
  InputGate(const T& input, std::size_t input_owner, std::size_t id);

  ~InputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
};


template <typename T>
class OutputGate final : public motion::OutputGate {
  using Base = motion::OutputGate;

 public:
  OutputGate(const astra::WirePointer<T>& parent, std::size_t id);

  ~OutputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  T GetResult() { return result_; }
  
 private:
  T result_;
};


template<typename T>
class AdditionGate final : public TwoGate {
  using Base = motion::TwoGate;
 
 public:
  AdditionGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b, std::size_t id);
  
  ~AdditionGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
};

template<typename T>
class MultiplicationGate final : public TwoGate {
  using Base = motion::TwoGate;
 
 public:
  MultiplicationGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b, std::size_t id);
  
  ~MultiplicationGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
};

template<typename T>
class DotProductGate final : public Gate {
 public:
  DotProductGate(const std::vector<motion::WirePointer>& vector_a, const std::vector<motion::WirePointer>& vector_b, std::size_t id);

  ~DotProductGate() final = default;

  DotProductGate(DotProductGate&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

 protected:
  std::vector<motion::WirePointer> parent_vector_a_;   
  std::vector<motion::WirePointer> parent_vector_b_;   
};

    
} //namespace encrypto::motion::proto::astra

namespace encrypto::motion::proto::astra {
    
template<typename T>
InputGate<T>::InputGate(const T& input, std::size_t input_owner, std::size_t id) {
  output_wires_ = {std::make_shared<astra::Wire<T>>((id == input_owner ? input : 0), 0, 0)};
  id_ = id;
  input_owner_ = input_owner;
}

template<typename T>
void InputGate<T>::EvaluateSetup() {
  auto my_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(my_wire);
  auto& lambdas = my_wire->GetMutableLambdas();
  switch(input_owner_) {
    case 0:
      switch(id_) {
        case 0:
          lambdas[0] = GetRandomValue(kKey_0_1);
          lambdas[1] = GetRandomValue(kKey_0_2);
          break;
        case 1:
          lambdas[0] = GetRandomValue(kKey_1_0);
          break;
        case 2:
          lambdas[1] = GetRandomValue(kKey_2_0);
          break;
      }
      break;
    case 1:
      switch(id_) {
        case 0:
          lambdas[0] = GetRandomValue(kKey_0_1);
          lambdas[1] = GetRandomValue(kKeyP_0);
          break;
        case 1:
          lambdas[0] = GetRandomValue(kKey_1_0);
          lambdas[1] = GetRandomValue(kKeyP_1);
          break;
        case 2:
          lambdas[1] = GetRandomValue(kKeyP_2);
          break;
      }
      break;
    case 2:
      switch(id_) {
        case 0:
          lambdas[0] = GetRandomValue(kKeyP_0);
          lambdas[1] = GetRandomValue(kKey_0_2);
          break;
        case 1:
          lambdas[0] = GetRandomValue(kKeyP_1);
          break;
        case 2:
          lambdas[0] = GetRandomValue(kKeyP_2);
          lambdas[1] = GetRandomValue(kKey_2_0);
          break;
      }
      break;    
  }
}

template<typename T>
void InputGate<T>::EvaluateOnline() {
  auto my_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(my_wire);
  auto& value = my_wire->GetMutableValue();
  
  if(input_owner_ == id_) {
    auto const& lambdas = my_wire->GetMutableLambdas();
    T lambda_x = lambdas[0] + lambdas[1];
    value += lambda_x;
    for(std::size_t i = 1u; i <= 2u; ++i) {
      if(input_owner_ == i) continue;
      Send(input_owner_, i, value);  
    }
  }
  else if(id_ != 0) {
    value = Receive(input_owner_, id_);
  }
}

template<typename T>
OutputGate<T>::OutputGate(const astra::WirePointer<T>& parent, std::size_t id) {
  id_ = id;
  parent_ = {parent};    
}

template<typename T>
void OutputGate<T>::EvaluateSetup() {}

//Only outputs to P1, as long as communicator is not implemented
//Uncomment and adapt the commented code below, when communicator is available
template<typename T>
void OutputGate<T>::EvaluateOnline() {
  auto my_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_.at(0));
  assert(my_wire);
  auto const& lambdas = my_wire->GetMutableLambdas();
  auto const& value = my_wire->GetMutableValue();

  switch(id_) {
    case 0:
      Send(0, 1, lambdas[1]);
      break;
    case 1:
      result_ = value - lambdas[0] - Receive(0, 1);
      break;
    case 2:
      break;
  }

  //Uncomment and adapt below code, when communicator is available
  /*
  switch(id_) {
    case 0:
      result_ = Receive(1, 0) - lambdas[0] - lambdas[1];
      break; 
    case 1:
      Send(1, 0, value);
      Send(1, 2, lambdas[0]);
      result_ = value - lambdas[0] - Receive(2, 1);
      break;
    case 2:
      Send(2, 1, lambdas[1]);
      result_ = value - lambdas[1] - Receive(1, 2);
      break;
  }
  */
}

template<typename T>
AdditionGate<T>::AdditionGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b, std::size_t id) {
  id_ = id;
  parent_a_ = {a};
  parent_b_ = {b};
  output_wires_ = {std::make_shared<astra::Wire<T>>(0, 0, 0)};
}

template<typename T>
void AdditionGate<T>::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
  assert(b_wire);
  
  auto& out_lambdas = out_wire->GetMutableLambdas();
  auto const& a_lambdas = a_wire->GetMutableLambdas();
  auto const& b_lambdas = b_wire->GetMutableLambdas();
  
  switch(id_) {
      case 0:
        out_lambdas[0] = a_lambdas[0] + b_lambdas[0];
        out_lambdas[1] = a_lambdas[1] + b_lambdas[1];
        break;
      case 1:
        out_lambdas[0] = a_lambdas[0] + b_lambdas[0];
        break;
      case 2:
        out_lambdas[1] = a_lambdas[1] + b_lambdas[1];
        break;
  }
}

template<typename T>
void AdditionGate<T>::EvaluateOnline() {
  if(id_ != 0) {
    auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
    assert(out_wire);
    auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
    assert(a_wire);
    auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
    assert(b_wire);
  
    auto& out_value = out_wire->GetMutableValue();
    auto const& a_value = a_wire->GetMutableValue();
    auto const& b_value = b_wire->GetMutableValue();
  
    out_value = a_value + b_value;
  }
}

template<typename T>
MultiplicationGate<T>::MultiplicationGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b, std::size_t id) {
  id_ = id;
  parent_a_ = {a};
  parent_b_ = {b};
  output_wires_ = {std::make_shared<astra::Wire<T>>(0, 0, 0)};
}

template<typename T>
void MultiplicationGate<T>::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  
  auto& out_lambdas = out_wire->GetMutableLambdas();
  
  switch(id_) {
      case 0:
        out_lambdas[0] = GetRandomValue(kKey_0_1);
        out_lambdas[1] = GetRandomValue(kKey_0_2);
        {
          auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
          assert(a_wire);
          auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
          assert(b_wire);
          
          auto const& a_lambdas = a_wire->GetMutableLambdas();
          auto const& b_lambdas = b_wire->GetMutableLambdas();
          
          T gamma_ab_1 = GetRandomValue(kKey_0_1);
          T lambda_a = a_lambdas[0] + a_lambdas[1];
          T lambda_b = b_lambdas[0] + b_lambdas[1];
          T gamma_ab = lambda_a * lambda_b;
          T gamma_ab_2 = gamma_ab - gamma_ab_1;
          Send(0, 2, gamma_ab_2);
        }
        break;
      case 1:
        out_lambdas[0] = GetRandomValue(kKey_1_0);
        //We store gamma_ab_1 in the free out_lambda space
        out_lambdas[1] = GetRandomValue(kKey_1_0);
        break;
      case 2:
        out_lambdas[1] = GetRandomValue(kKey_2_0);
        //We store gamma_ab_2 in the free out_lambda space
        out_lambdas[0] = Receive(0, 2);
        break;
  }
}

template<typename T>
void MultiplicationGate<T>::EvaluateOnline() {
  if(id_ != 0) {
    auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
    assert(out_wire);
    auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
    assert(a_wire);
    auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
    assert(b_wire);
  
    auto& out_value = out_wire->GetMutableValue();
    auto const& a_value = a_wire->GetMutableValue();
    auto const& b_value = b_wire->GetMutableValue();
    
    auto& out_lambdas = out_wire->GetMutableLambdas();
    auto const& a_lambdas = a_wire->GetMutableLambdas();
    auto const& b_lambdas = b_wire->GetMutableLambdas();
    
    switch(id_) {
      case 1:
        out_value = -(a_value * b_lambdas[0]) - b_value * a_lambdas[0] + out_lambdas[0] + out_lambdas[1];
        //Uncomment this, when online functionality is implemented
        /*
        Send(1, 2, out_value);
        out_value += Receive(2, 1)
        */
        break;
      case 2:
        out_value = a_value * b_value - a_value * b_lambdas[1] - b_value * a_lambdas[1] + out_lambdas[1] + out_lambdas[0];
        //Uncomment this, when online functionality is implemented
        /*
        Send(2, 1, out_value);
        out_value += Receive(1, 2)
        */
        break;
    }
  }
}

template<typename T>
DotProductGate<T>::DotProductGate(const std::vector<motion::WirePointer>& vector_a, const std::vector<motion::WirePointer>& vector_b, std::size_t id)
: parent_vector_a_{vector_a}, parent_vector_b_{vector_b} {
  assert(parent_vector_a_.size() > 0);
  assert(parent_vector_a_.size() == parent_vector_b_.size());
  id_ = id;
  output_wires_ = {std::make_shared<astra::Wire<T>>(0, 0, 0)};
}

template<typename T>
void DotProductGate<T>::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  
  auto& out_lambdas = out_wire->GetMutableLambdas();
  
  switch(id_) {
      case 0:
        out_lambdas[0] = GetRandomValue(kKey_0_1);
        out_lambdas[1] = GetRandomValue(kKey_0_2);
        {
          T gamma_ab_1 = GetRandomValue(kKey_0_1);
          T gamma_ab{0};
          //Compute gamma_ab
          for(std::size_t i = 0; i != parent_vector_a_.size(); ++i) {
            auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_vector_a_.at(i));
            assert(a_wire);
            auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_vector_b_.at(i));
            assert(b_wire);
            
            auto const& a_lambdas = a_wire->GetMutableLambdas();
            auto const& b_lambdas = b_wire->GetMutableLambdas();
            
            T lambda_a = a_lambdas[0] + a_lambdas[1];
            T lambda_b = b_lambdas[0] + b_lambdas[1];
            gamma_ab += lambda_a * lambda_b;
          }
          T gamma_ab_2 = gamma_ab - gamma_ab_1;
          Send(0, 2, gamma_ab_2);
        }
        break;
      case 1:
        out_lambdas[0] = GetRandomValue(kKey_1_0);
        //We store gamma_ab_1 in the free out_lambda space
        out_lambdas[1] = GetRandomValue(kKey_1_0);
        break;
      case 2:
        out_lambdas[1] = GetRandomValue(kKey_2_0);
        //We store gamma_ab_2 in the free out_lambda space
        out_lambdas[0] = Receive(0, 2);
        break;
  }
}

template<typename T>
void DotProductGate<T>::EvaluateOnline() {
  if(id_ != 0) {
    
    auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
    assert(out_wire);
  
    auto& out_value = out_wire->GetMutableValue();
    auto& out_lambdas = out_wire->GetMutableLambdas();
    
    out_value = 0;
    for(std::size_t i = 0; i != parent_vector_a_.size(); ++i) {
      auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_vector_a_.at(i));
      assert(a_wire);
      auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_vector_b_.at(i));
      assert(b_wire);
      auto const& a_value = a_wire->GetMutableValue();
      auto const& b_value = b_wire->GetMutableValue();
      auto const& a_lambdas = a_wire->GetMutableLambdas();
      auto const& b_lambdas = b_wire->GetMutableLambdas();
      
      switch(id_) {
        case 1:
          out_value += -(a_value * b_lambdas[0]) - b_value * a_lambdas[0];
          break;
        case 2:
          out_value += a_value * b_value - a_value * b_lambdas[1] - b_value * a_lambdas[1];
          break;
      }
    }
    
    switch(id_) {
      case 1:
        out_value += out_lambdas[0] + out_lambdas[1];
        break;
      case 2:
        out_value +=  out_lambdas[1] + out_lambdas[0];
        break;
    }
    
    //Uncomment this, when online functionality is implemented
    /*
    switch(id_) {
      case 1:
        out_value += out_lambdas[0] + out_lambdas[1];
        Send(1, 2, out_value);
        out_value += Receive(2, 1)
        break;
      case 2:
        out_value +=  out_lambdas[1] + out_lambdas[0]
        Send(2, 1, out_value);
        out_value += Receive(1, 2)
        break;
    }
    */
  }
}
  
} //namespace encrypto::motion::proto::astra



int main() {
    namespace motion = encrypto::motion;
    namespace astra = encrypto::motion::proto::astra;
    astra::InputGate<uint64_t> a_1(127, 0, 0), b_1(-1, 0, 1), c_1(-1, 0, 2);
    astra::InputGate<uint64_t> a_2(-1, 1, 0), b_2(3, 1, 1), c_2(-1, 1, 2);
    astra::InputGate<uint64_t> a_3(-1, 2, 0), b_3(-1, 2, 1), c_3(5, 2, 2);
    
    astra::InputGate<uint64_t> a_p2(-1, 1, 0), b_p2(6, 1, 1), c_p2(-1, 1, 2);
    astra::InputGate<uint64_t> a_p3(-1, 2, 0), b_p3(-1, 2, 1), c_p3(10, 2, 2);
    
    
    astra::InputGate<uint64_t> a_q1(1, 0, 0), b_q1(-1, 0, 1), c_q1(-1, 0, 2);
    astra::InputGate<uint64_t> a_q2(-1, 1, 0), b_q2(20, 1, 1), c_q2(-1, 1, 2);
    astra::InputGate<uint64_t> a_q3(-1, 2, 0), b_q3(-1, 2, 1), c_q3(15, 2, 2);
    
    
    astra::AdditionGate<uint64_t> a(std::dynamic_pointer_cast<astra::Wire<uint64_t>>(a_1.GetOutputWires().at(0)),
                                    std::dynamic_pointer_cast<astra::Wire<uint64_t>>(a_2.GetOutputWires().at(0)),
                                    0), 
                                  b(std::dynamic_pointer_cast<astra::Wire<uint64_t>>(b_1.GetOutputWires().at(0)),
                                    std::dynamic_pointer_cast<astra::Wire<uint64_t>>(b_2.GetOutputWires().at(0)),
                                    1), 
                                  c(std::dynamic_pointer_cast<astra::Wire<uint64_t>>(c_1.GetOutputWires().at(0)),
                                    std::dynamic_pointer_cast<astra::Wire<uint64_t>>(c_2.GetOutputWires().at(0)),
                                    2);
    
    astra::MultiplicationGate<uint64_t> a_m(std::dynamic_pointer_cast<astra::Wire<uint64_t>>(a.GetOutputWires().at(0)),
                                            std::dynamic_pointer_cast<astra::Wire<uint64_t>>(a_3.GetOutputWires().at(0)),
                                            0), 
                                        b_m(std::dynamic_pointer_cast<astra::Wire<uint64_t>>(b.GetOutputWires().at(0)),
                                            std::dynamic_pointer_cast<astra::Wire<uint64_t>>(b_3.GetOutputWires().at(0)),
                                            1), 
                                        c_m(std::dynamic_pointer_cast<astra::Wire<uint64_t>>(c.GetOutputWires().at(0)),
                                            std::dynamic_pointer_cast<astra::Wire<uint64_t>>(c_3.GetOutputWires().at(0)),
                                            2);
    
    astra::DotProductGate<uint64_t> a_dp({
                                           a_m.GetOutputWires().at(0),
                                           a_p2.GetOutputWires().at(0),
                                           a_p3.GetOutputWires().at(0)
                                         },
                                         {
                                           a_q1.GetOutputWires().at(0),
                                           a_q2.GetOutputWires().at(0),
                                           a_q3.GetOutputWires().at(0)
                                         },
                                         0), 
                                    b_dp({
                                           b_m.GetOutputWires().at(0),
                                           b_p2.GetOutputWires().at(0),
                                           b_p3.GetOutputWires().at(0)
                                         },
                                         {
                                           b_q1.GetOutputWires().at(0),
                                           b_q2.GetOutputWires().at(0),
                                           b_q3.GetOutputWires().at(0)
                                         },
                                         1),
                                    c_dp({
                                           c_m.GetOutputWires().at(0),
                                           c_p2.GetOutputWires().at(0),
                                           c_p3.GetOutputWires().at(0)
                                         },
                                         {
                                           c_q1.GetOutputWires().at(0),
                                           c_q2.GetOutputWires().at(0),
                                           c_q3.GetOutputWires().at(0)
                                         },
                                         2);
    
    
    astra::OutputGate<uint64_t> a_o(std::dynamic_pointer_cast<astra::Wire<uint64_t>>(a_dp.GetOutputWires().at(0)), 0),
                                b_o(std::dynamic_pointer_cast<astra::Wire<uint64_t>>(b_dp.GetOutputWires().at(0)), 1),
                                c_o(std::dynamic_pointer_cast<astra::Wire<uint64_t>>(c_dp.GetOutputWires().at(0)), 2);
    
    
    a_1.EvaluateSetup();
    b_1.EvaluateSetup();
    c_1.EvaluateSetup();
    
    b_2.EvaluateSetup();
    a_2.EvaluateSetup();
    c_2.EvaluateSetup();
    
    c_3.EvaluateSetup();
    a_3.EvaluateSetup();
    b_3.EvaluateSetup();
    
    b_p2.EvaluateSetup();
    a_p2.EvaluateSetup();
    c_p2.EvaluateSetup();
    
    c_p3.EvaluateSetup();
    a_p3.EvaluateSetup();
    b_p3.EvaluateSetup();
    
    a_q1.EvaluateSetup();
    b_q1.EvaluateSetup();
    c_q1.EvaluateSetup();
    
    b_q2.EvaluateSetup();
    a_q2.EvaluateSetup();
    c_q2.EvaluateSetup();
    
    c_q3.EvaluateSetup();
    a_q3.EvaluateSetup();
    b_q3.EvaluateSetup();
    
    a.EvaluateSetup();
    b.EvaluateSetup();
    c.EvaluateSetup();
    
    a_m.EvaluateSetup();
    b_m.EvaluateSetup();
    c_m.EvaluateSetup();
    
    a_dp.EvaluateSetup();
    b_dp.EvaluateSetup();
    c_dp.EvaluateSetup();
                         
    a_o.EvaluateSetup();
    b_o.EvaluateSetup();
    c_o.EvaluateSetup();
    
    
    
    a_1.EvaluateOnline();
    b_1.EvaluateOnline();
    c_1.EvaluateOnline();
    
    b_2.EvaluateOnline();
    a_2.EvaluateOnline();
    c_2.EvaluateOnline();
    
    c_3.EvaluateOnline();
    a_3.EvaluateOnline();
    b_3.EvaluateOnline();
    
    b_p2.EvaluateOnline();
    a_p2.EvaluateOnline();
    c_p2.EvaluateOnline();
    
    c_p3.EvaluateOnline();
    a_p3.EvaluateOnline();
    b_p3.EvaluateOnline();
    
    a_q1.EvaluateOnline();
    b_q1.EvaluateOnline();
    c_q1.EvaluateOnline();
    
    b_q2.EvaluateOnline();
    a_q2.EvaluateOnline();
    c_q2.EvaluateOnline();
    
    c_q3.EvaluateOnline();
    a_q3.EvaluateOnline();
    b_q3.EvaluateOnline();
    
    a.EvaluateOnline();
    b.EvaluateOnline();
    c.EvaluateOnline();
    
    a_m.EvaluateOnline();
    b_m.EvaluateOnline();
    c_m.EvaluateOnline();
    
    {
      //Do exchange here, as we have no online functionality
      auto my_wire_b = std::dynamic_pointer_cast<astra::Wire<uint64_t>>(b_m.GetOutputWires().at(0));
      assert(my_wire_b);
      auto my_wire_c = std::dynamic_pointer_cast<astra::Wire<uint64_t>>(c_m.GetOutputWires().at(0));
      assert(my_wire_c);
      auto& b_value = my_wire_b->GetMutableValue();
      auto& c_value = my_wire_c->GetMutableValue();
      auto tmp = b_value;
      b_value += c_value;
      c_value += tmp;
    }
    
    a_dp.EvaluateOnline();
    b_dp.EvaluateOnline();
    c_dp.EvaluateOnline();
    
    {
      //Do exchange here, as we have no online functionality
      auto my_wire_b = std::dynamic_pointer_cast<astra::Wire<uint64_t>>(b_dp.GetOutputWires().at(0));
      assert(my_wire_b);
      auto my_wire_c = std::dynamic_pointer_cast<astra::Wire<uint64_t>>(c_dp.GetOutputWires().at(0));
      assert(my_wire_c);
      auto& b_value = my_wire_b->GetMutableValue();
      auto& c_value = my_wire_c->GetMutableValue();
      auto tmp = b_value;
      b_value += c_value;
      c_value += tmp;
    }                     
    a_o.EvaluateOnline();
    b_o.EvaluateOnline();
    c_o.EvaluateOnline();
    
    /*
    auto my_wire_b = std::dynamic_pointer_cast<Wire<uint64_t>>(b.GetOutputWires().at(0));
    assert(my_wire_b);
    auto my_wire_c = std::dynamic_pointer_cast<Wire<uint64_t>>(c.GetOutputWires().at(0));
    assert(my_wire_c);
    auto lambda_x_1 = my_wire_b->GetMutableLambdas()[0];
    auto lambda_x_2 = my_wire_c->GetMutableLambdas()[1];
    auto value = my_wire_b->GetMutableValue();
    
    std::cout << "value: " << value << std::endl;
    
    //auto result = b.input_ - b.lambda_x_i_[0] - c.lambda_x_i_[1];
    auto result = value - lambda_x_1 - lambda_x_2;
    */
    std::cout << b_o.GetResult() << std::endl;
    
    
}