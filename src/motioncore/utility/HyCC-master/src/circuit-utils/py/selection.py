#!/bin/python
from __future__ import print_function

import sys
import os
import os.path
import itertools
import collections
from enum import Enum
from pathlib import Path

from reader import CircuitReader

Sharing = Enum('Sharing', 'arith bool_depth bool_size')

class Module:
    def __init__(self, path):
        self.path = path

        self.circuit = CircuitReader(open(path, "rb"))
        self.circuit.read()

    @property
    def name(self):
        return self.circuit.name

    @property
    def calls(self):
        return self.circuit.calls

    @property
    def inputs(self):
        return self.circuit.inputs

    @property
    def outputs(self):
        return self.circuit.outputs

    def gate_stats(self):
        return self.circuit.gate_stats()

    def sharing(self):
        if '@arith' in self.path:
            return Sharing.arith
        if '@bool_depth' in self.path:
            return Sharing.bool_depth
        if '@bool_size' in self.path:
            return Sharing.bool_size
        raise Exception('file-name must contain @arith, @bool_depth or @bool_size: {}'.format(self.path))

### For Testing
class FakeCall:
    def __init__(self, name):
        self.name = name

class FakeModule:
    def __init__(self, name, sharing, calls, gates):
        self.name = name
        self.sharing_ = sharing
        self.calls_ = calls
        self.gates = gates

    def add_call(self, name):
        self.calls_.append(name)

    @property
    def calls(self):
        return map(FakeCall, self.calls_)

    def sharing(self):
        return self.sharing_
### Testing

class Analyzer:
    def __init__(self):
        # A module can have different versions (arith/boolean)
        self.modules = collections.defaultdict(dict)

        self.callees = collections.defaultdict(set)
        self.callers = collections.defaultdict(set)
        self.number_of_calls = collections.defaultdict(lambda: collections.defaultdict(int))

    def read_circ(self, path):
        module = Module(path)
        if module.name in self.modules and module.sharing() in self.modules[module.name]:
            raise Exception("{} with sharing {} already exists".format(module.name, module.sharing()))
        self.modules[module.name][module.sharing()] = module

    def read_cmb(self, path):
        folder, filename = os.path.split(path)

        with open(path, 'r') as file:
            for line in file.readlines():
                circ = line.split(":")[0].strip()
                self.read_circ(os.path.join(folder, circ))

    def read_folder(self, folder):
        for file in os.listdir(folder):
            if file.endswith('.circ'):
                self.read_circ(os.path.join(folder, file))

    ### testing
    def generate_fake(self, depth):
        import random

        module = FakeModule('mpc_main', Sharing.bool_size, [], [])
        self.modules['mpc_main'] = dict([(Sharing.bool_size, module)])

        for i in range(0, depth):
            for k in range(0, random.randint(0, 4)): # 4
                new_name = 'Module ' + str(k + len(self.modules))

                if new_name in self.modules:
                    module = self.modules[new_name]
                else:
                    module = FakeModule(new_name,
                                        Sharing.bool_size,
                                        [], [])
                    self.modules[new_name] = dict([(Sharing.bool_size, module)])

                while True:
                    existing = random.choice(self.modules.keys())
                    if existing == new_name:
                        continue

                    self.modules[existing][Sharing.bool_size].add_call(new_name)

                    if random.random() < 0.7:
                        break


    def analyze(self):
        for modules in self.modules.values():
            m = next(iter(modules.values()))

            for call in m.calls:
                self.callees[m.name].add(call.name)
                self.callers[call.name].add(m.name)
                self.number_of_calls[m.name][call.name] += 1

    def stats(self):
        print("Modules: {}\n".format(len(self.modules)))

        for name, modules in self.modules.items():
            print(name)
            print("  Possible sharings:", " ".join(sorted([m.sharing().name for m in modules.values()])))
            print("  Calls:")
            for call in self.number_of_calls[name]:
                print("    {} x {}".format(call, self.number_of_calls[name][call]))
            print("")

    def find_sub_graphs(self):
        subgraphs = []

        for (module, incoming) in self.callers.items():
            if len(incoming) == 0: # Skip main
                continue

            observed = set()
            def search(module):
                observed.add(module)

                for outgoing in self.callees[module]:
                    if outgoing in observed:
                        continue
                    search(outgoing)
            search(module)

            node = None
            found = False
            for module in observed:
                for incoming in self.callees[module]:
                    if not incoming in observed:
                        if node is None:
                            node = module
                        elif node != incoming:
                            found = True
                            break

            if len(observed) > 1 and not found:
                subgraphs.append(observed)

        return subgraphs

    def write_dot(self, out):
        with open(out, 'w') as dot:
            dot.write('digraph Calls {\n')

            for module in self.modules.values():
                m = next(iter(module.values()))

                for callee in self.callees[m.name]:
                    dot.write('"{}" -> "{}";\n'.format(m.name, callee))

            dot.write('}\n')


class ProtocolSelection:
    def __init__(self, analyzer, costs):
        self.analyzer = analyzer
        self.costs = costs


    def share_combinations(self, modules):
        names = sorted(modules)
        protocols = [Sharing.bool_size, Sharing.bool_depth, Sharing.arith]
        for sharing in itertools.product(protocols, repeat=len(names)):
            # Limit to valid sharing at start?
            yield dict(zip(names, sharing))

    def cost(self, variant):
        stats = variant.gate_stats()
        sharing = variant.sharing()

        total = 0

        for ((gate, width), count) in stats.items():
            if not gate in self.costs:
                if gate == 'sub':
                    gate = 'add' # ~ plus neg?
                elif gate == 'or':
                    gate = 'and' # ~ not(and(not(x), not(y))) and not ~ free
                elif gate == 'not' or gate == 'neg':
                    # not ~ free
                    # neg ~ free?
                    continue
                elif gate == 'split' or gate == 'combine':
                    # ignore
                    continue
                else:
                    raise Exception('Unknown gate kind: {}'.format(gate))

            # Select optimal gate for sharing
            if sharing == Sharing.bool_depth:
                if gate == 'add':
                    gate = 'adddo'
                elif gate == 'mul':
                    gate = 'muldo'

            total += self.costs[gate][sharing][width] * count

        return total

    def conversion_cost(self, source, target):
        (sname, ssharing) = source
        (tname, tsharing) = target

        if ssharing == tsharing:
            return 0

        def sharing_cost(source, target, width):
            if source == Sharing.bool_size:
                if target == Sharing.bool_depth:
                    return self.costs['y2b'][width]
                else:
                    assert target == Sharing.arith
                    return self.costs['b2a'][width] # y2a ~= b2a
            elif source == Sharing.bool_depth:
                if target == Sharing.bool_size:
                    return self.costs['b2y'][width]
                else:
                    assert target == Sharing.arith
                    return self.costs['b2a'][width]
            else:
                assert source == Sharing.arith
                if target == Sharing.bool_size:
                    return self.costs['a2y'][width]
                else:
                    assert target == Sharing.bool_depth
                    return self.costs['a2y'][width] # a2y ~= a2b

        total = 0

        # input conversion
        variant = self.analyzer.modules[tname][tsharing]
        for in_ in variant.inputs:
            total += sharing_cost(ssharing, tsharing, in_.width)

        # output conversion
        for out in variant.outputs:
            total += sharing_cost(tsharing, ssharing, out.width)

        return total

    def run(self, modules):
        execution_cost = dict()

        for module in modules:
            variants = self.analyzer.modules[module]
            for variant in variants:
                execution_cost[(module, variant)] = self.cost(variants[variant])

        minimum = float('inf')
        result = None

        results = []

        for combination in self.share_combinations(modules):
            cost = 0

            # Circuit Execution Cost
            skip = False
            for (name, sharing) in combination.items():
                try:
                    cost += execution_cost[(name, sharing)]
                except KeyError:
                    # Type of sharing does not exist, probably Arithmetic
                    skip = True
                    break

            if skip:
                continue

            # Conversion Costs
            for (name, sharing) in combination.items():
                for other in self.analyzer.callees[name]:
                    conversion = self.conversion_cost((name, sharing), (other, combination[other]))
                    cost += conversion * self.analyzer.number_of_calls[name][other]

            if cost < minimum:
                minimum = cost
                # result = combination
                results.append((combination, cost))

        return results

def load_costs(path):
    import json

    def object_pairs_hook(pairs):
        def map_key(k_v):
            k,v = k_v

            if k == 'bool':
                k = Sharing.bool_depth
            elif k == 'yao':
                k = Sharing.bool_size
            elif k == 'arith':
                k = Sharing.arith
            elif k in ['1', '8', '16', '32']:
                k = int(k)

            return (k, v)

        pairs = map(map_key, pairs)
        return dict(pairs)

    costs = json.load(open(path, 'r'), object_pairs_hook=object_pairs_hook)
    return costs

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Protocol selection')

    parser.add_argument('circuit', help='path to folder with circuits (.circ) or a single .cmb file')
    parser.add_argument('cost', help='path to cost JSON file')
    args = parser.parse_args()
    costs = load_costs(args.cost)

    # append supplied path to currend directory
    dirname = Path.cwd() / Path(sys.argv[1])
    print("Directory:", dirname)
    os.chdir(dirname)

    analyzer = Analyzer()
    
    if args.circuit.endswith('.cmb'):
        analyzer.read_cmb(args.circuit)
    else:
        analyzer.read_folder(args.circuit)

    analyzer.analyze()

    analyzer.stats()
    analyzer.write_dot("graph.dot")

    print("Subgraphs:")
    subgraphs = analyzer.find_sub_graphs()
    for subgraph in sorted(subgraphs, key=len, reverse=True):
        print(" ", subgraph)
    print("")

    # Protocol selection using a subgraph
    # modules = subgraphs[X]
    # Protocol selection for all modules
    modules = [name for name in analyzer.modules.keys()]
    
    protocol_selection = ProtocolSelection(analyzer, costs)
    results = protocol_selection.run(modules)
    sorted_results = sorted(results, key=lambda t: t[1], reverse=True)

    print("== Protocol selection ==\n")
    for (selection, cost) in sorted_results:
        print("Cost: {:.0f}".format(cost))
        for name in sorted(modules):
            print("  {}: {}".format(name, selection[name]))
        print("")

    # when analyzing a folder of circuts, write smallest cost estimate to .cmb file
    if not args.circuit.endswith('.cmb'):
        with open("ps_optimized.cmb", "w") as of:
            (selection, cost) = sorted_results[-1]
            for name in sorted(modules):
                of.write("{}@{}.circ\n".format(name, str(selection[name])[8:]))
