import collections
import json


def convert(text):
    lines = text.splitlines()

    operations = collections.defaultdict(dict)

    for line in lines[4:]:
        if line.startswith('sbox'): # Skip over *
            continue

        splitted = line.strip().split()

        op = splitted[0]
        timings = {1: float(splitted[1]),
                   8: float(splitted[2]),
                   16: float(splitted[3]),
                   32: float(splitted[4]) }

        if op.endswith('bool'):
            operations[op[:-4]]['bool'] = timings
        elif op.endswith('yao'):
            operations[op[:-3]]['yao'] = timings
        elif op.endswith('arith'):
            operations[op[:-5]]['arith'] = timings

        if '2' in op:
            operations[op] = timings

    return operations

# Obtained with ABY .. bench_operations
costs = """
Base OTs:    0
Op    1-bit     8-bit     16-bit     32-bit     64-bit
-----------------------------------------------
xorbool    205.544    120.112    195.179    125.154    189.795
andbool    322.521    320.293    313.943    315.589    317.013
addsobool    129.796    637.953    1070.69    1905.64    3626.46
adddobool    294.112    465.945    524.457    602.37    646.834
adddovecbool    234.807    616.533    649.626    657.659    731.469
mulsobool    315.436    717.302    1088.29    2121.48    3902.77
muldobool    318.94    654.57    766.692    1044.67    1465.5
mulsovecbool    318.247    740.136    1265.37    2142.29    3933.75
muldovecbool    314.69    747.069    857.161    1161.19    1490.29
cmpsobool    319.328    665.959    1124.82    1927.67    3705.1
cmpdobool    317.219    499.259    526.257    550.834    626.32
eqbool    200.331    429.922    439.933    529.283    618.575
muxbool    320.388    322.502    324.969    316.438    317.34
muxvecbool    325.364    310.333    322.711    324.6    315.63
invbool    117.708    203.205    113.149    207.055    111.965
sboxsobool    *    199.622    536.569    628.113    545.301    623.819
sboxdobool    *    118.711    521.291    439.959    517.408    436.191
sboxdovecbool    *    206.12    531.302    616.458    562.379    583.287
xoryao    323.464    314.425    310.38    322.615    326.53
andyao    318.946    326.198    328.816    314.308    310.849
addyao    316.939    317.848    320.007    314.941    328.798
mulyao    318.776    323.827    320.097    410.183    828.301
cmpyao    325.187    317.956    316.21    313.833    320.327
eqyao    309.717    323.07    319.867    316.492    319.963
muxyao    330.528    318.433    325.117    319.27    323.357
invyao    212.694    214.483    229.117    222.065    217.038
sboxsoyao    *    215.014    216.408    220.515    219.753    219.428
addarith    214.449    108.999    202.045    116.869    201.625
mularith    323.99    425.06    324.338    416.112    327.226
y2b    312.428    324.848    317.608    318.788    320.77
b2a    314.401    328.788    328.053    326.316    325.492
b2y    329.222    318.638    316.215    319.556    315.076
a2y    325.398    318.621    314.128    327.097    317.666
"""

json.dump(convert(costs), open('costs.json', 'w'), indent=4)