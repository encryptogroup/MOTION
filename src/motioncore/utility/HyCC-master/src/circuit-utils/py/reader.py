#!/bin/python
from __future__ import print_function

import sys
import struct

class BinaryReader:
    def __init__(self, stream):
        self.stream = stream

    def unpack(self, fmt, length):
        return struct.unpack(fmt, self.stream.read(length))[0]

    def read_uint8(self):
        return self.unpack('<B', 1)

    def read_uint32(self):
        return self.unpack('<I', 4)

    def read_string(self):
        string = ""

        while True:
            char = self.stream.read(1)
            if ord(char) == 0:
                break
            string += char.decode('ascii')

        return string

class DataType(object):
    def __init__(self, kind):
        self.kind = kind

    def bit_width(self):
        raise NotImplementedError("not implemented for base")

class IntegerType(DataType):
    def __init__(self, signed, width):
        DataType.__init__(self, "integer")

        self.signed = signed
        self.width = width

    def bit_width(self):
        return self.width

    def __str__(self):
        if self.signed:
            return "int{}".format(self.width)
        else:
            return "uint{}".format(self.width)

class ArrayType(DataType):
    def __init__(self, inner, length):
        DataType.__init__(self, "array")

        self.inner = inner
        self.length = length

    def bit_width(self):
        return self.inner.bit_width() * self.length

    def __str__(self):
        return "{}[{}]".format(str(self.inner), self.length)

class StructType(DataType):
    def __init__(self):
        DataType.__init__(self, "struct")

        self.members = []

    def add_member(self, name, ctype):
        self.members.append(Variable(name, ctype))

    def bit_width(self):
        return sum([m.ctype.bit_width() for m in self.members])

    def __str__(self):
        return "{ " + "; ".join(map(str, self.members)) + "}"

class Variable(object):
    def __init__(self, name, ctype, owner = None):
        self.name = name
        self.ctype = ctype
        self.owner = None

    def __str__(self):
        return "{}: {}".format(self.name, self.ctype)

class FunctionCall(object):
    def __init__(self, name, args, returns):
        self.name = name
        self.args = args
        self.returns = returns

    def __str__(self):
        return "{} ({}) -> {}".format(self.name,
            ",".join(map(str, self.args)),
            ",".join(map(str, self.returns)))

class Endpoint(object):
    def __init__(self, name, fanins=[], width = 0):
        self.name = name
        self.fanins = []
        self.width = width

class CircuitReader:
    def __init__(self, stream):
        self.reader = BinaryReader(stream)

    def read(self):
        magic = self.reader.read_uint32()
        assert magic == 0xCB11C06C

        version = self.reader.read_uint8()
        assert version == 0x5

        num_gates = self.reader.read_uint32()
        num_inputs = self.reader.read_uint32()
        num_outputs = self.reader.read_uint32()
        num_input_vars = self.reader.read_uint32()
        num_output_vars = self.reader.read_uint32()
        num_function_calls = self.reader.read_uint32()

        self.name = self.reader.read_string()

        # Read properties
        self.properties = []
        while True:
            property_name = self.reader.read_string()
            if not property_name:
                break
            property_type = self.read_type()
            self.properties.append(Variable(property_name, property_type))

        self.input_vars = []
        # Reading input variables
        for i in range(0, num_input_vars):
            name = self.reader.read_string()
            owner = self.reader.read_uint8()
            ctype = self.read_type()
            self.input_vars.append(Variable(name, ctype, owner))

        # Reading output variables
        self.output_vars = [self.read_variable() for i in range(0, num_output_vars)]

        # Read variables used by function calls
        self.calls = []
        for i in range(0, num_function_calls):
            name = self.reader.read_string()
            num_args = self.reader.read_uint32()
            num_returns = self.reader.read_uint32()

            returns = [self.read_variable() for j in range(0, num_returns)]
            args = [self.read_variable() for j in range(0, num_args)]

            self.calls.append(FunctionCall(name, args, returns))

        partitioning = self.read_input_partitioning()
        self.inputs = []
        self.create_inputs(partitioning)

        self.read_gates(num_gates)


    def read_variable_data(self):
        value = 0
        bit_pos = 0;
        cont = True

        while cont:
            if bit_pos + 7 >= 64:
                raise "Extended header of type too long"

            b = self.reader.read_uint8()
            value |= (b & 0x7f) << bit_pos;
            bit_pos += 7
            cont = b >> 7

        return value

    def read_variable(self):
        name = self.reader.read_string()
        ctype = self.read_type()
        return Variable(name, ctype)

    def read_type(self):
        header = self.reader.read_uint8()

        type_id = header & 0x3f
        length = self.read_variable_data()
        if type_id == 1:
            return IntegerType(True, length)
        elif type_id == 2:
            return IntegerType(False, length)
        elif type_id == 3:
            return ArrayType(self.read_type(), length)
        elif type_id == 4:
            struct = StructType()
            for i in range(length):
                struct.add_member(self.reader.read_string(), self.read_type())
            return struct
        else:
            print(type_id)
            raise Exception

    def read_input_partitioning(self):
        partitioning = self.reader.read_uint8()

        kind = partitioning >> 6
        size = partitioning & 0x3f

        # Extended header
        if size == 0:
            size = self.read_variable_data()

        if kind == 0:
            return ("atomic", size, [])
        elif kind == 1:
            return ("array", size, [self.read_input_partitioning()])
        elif kind == 2:
            return ("struct", size,
                [self.read_input_partitioning() for i in range(0, size)])
        else:
            raise Exception

    def create_inputs(self, partitioning):
        (kind, size, partitioning) = partitioning

        if kind == "atomic":
            self.inputs.append(Endpoint("input", width=size))
        elif kind == "array":
            for i in range(0, size):
                self.create_inputs(partitioning[0])
        elif kind == "struct":
            for p in partitioning:
                self.create_inputs(p)


    def read_gates(self, num_gates):
        # Implicit INPUT gates
        id_to_endpoint = [Endpoint("input: " + str(i), width=e.width) for (i, e) in enumerate(self.inputs)]

        for i in range(0, num_gates):
            data = self.reader.read_uint8()

            binary = {
                0x01: 'and',
                0x02: 'or',
                0x03: 'xor',
                0xc1: 'add',
                0xc2: 'sub',
                0xc4: 'mul'
            }

            unary = {
                0x04: 'not',
                0xc3: 'neg'
            }

            if data in binary:
                fanin0 = id_to_endpoint[self.reader.read_uint32()]
                fanin1 = id_to_endpoint[self.reader.read_uint32()]

                id_to_endpoint.append(Endpoint(binary[data], fanins=[fanin0, fanin1], width=fanin0.width))
            elif data in unary:
                fanin0 = id_to_endpoint[self.reader.read_uint32()]
                id_to_endpoint.append(Endpoint(unary[data], fanins=[fanin0], width=fanin0.width))
            elif data == 0x05:
                id_to_endpoint.append(Endpoint("one"))
            elif data == 0xc5:
                width = self.read_variable_data()
                value = self.read_variable_data()
                id_to_endpoint.append(Endpoint("const", width=width))
            elif (data & 0xc0) == 0x40: # combine
                num_fanins = (data & 0x3f) + 1
                fanins = [id_to_endpoint[self.reader.read_uint32()] for i in range(0, num_fanins)]
                id_to_endpoint.append(Endpoint("combine", fanins=fanins, width=num_fanins))
            elif (data & 0xe0) == 0xe0: # split
                # width = data & 0x2f
                fanin0 = id_to_endpoint[self.reader.read_uint32()]

                num_fanouts = fanin0.width
                for i in range(0, num_fanouts):
                    id_to_endpoint.append(Endpoint("split", width=1)) # TODO: check correctness
            else:
                raise NotImplementedError("not implemented: " + hex(data))

        # Read OUTPUT gates
        self.outputs = []
        for var in self.output_vars:
            width = var.ctype.bit_width()
            while width > 0:
                fanin = id_to_endpoint[self.reader.read_uint32()]
                e = Endpoint("output {} {}".format(var.name, fanin), fanins=[fanin], width=fanin.width)
                id_to_endpoint.append(e)
                self.outputs.append(e)
                width -= fanin.width

        self.id_to_endpoint = id_to_endpoint

    def gate_stats(self):
        from collections import Counter

        counter = Counter()

        for endpoint in self.id_to_endpoint:
            name = endpoint.name
            if name.startswith('input') or name.startswith('output'):
                continue

            counter[(endpoint.name, endpoint.width)] += 1

        return counter

if __name__ == "__main__":
    reader = CircuitReader(open(sys.argv[1], "rb"))
    reader.read()

    print("=== {} ===".format(reader.name))

    print("Gates Stats:")
    for ((name, width), count) in reader.gate_stats().items():
        print(" {:>2}-bit {:7} x {}".format(width, name, count))
    print("Input Vars:")
    for input_ in reader.input_vars:
        print(" {}".format(input_))
    print("Input Gates: {}".format(len(reader.inputs)))
    print("Output Vars:")
    for output in reader.output_vars:
        print(" {}".format(output))
    print("Output Gates: {}".format(len(reader.outputs)))
    print("Function calls:")
    for call in reader.calls:
        print(" {}".format(call))
