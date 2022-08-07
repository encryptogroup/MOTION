Soon, here will be the code for our accepted paper at ESORICS'22:
K. Hamacher, T. Kussel, T. Schneider and O. Tkachenko. "PEA: Practical Private Epistasis Analysis
using MPC."

Some parts of our implementation are already in this repository!

- Three-halves garbling (Rosulek and Roy,
  CRYPTO'21): [`src/motioncore/protocols/garbled_circuit`](https://encrypto.de/code/3H-GC)
- 1-out-of-N OT extension (Kolesnikov and Kumaresan, CRYPTO'13): `src/motioncore/oblivious_transfer/1_out_of_n`
- Arithmetic greater than gate (our ESORICS'22
  paper): `src/motioncore/protocols/arithmetic_gmw/arithmetic_gmw_gate.{cpp,h}`
