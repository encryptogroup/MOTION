# Tutorial Examples

---

We implemented three example programs to help a better understanding of Secure
Multi-Party Computation and moreover of our framework. They illustrate a variety
of common functionality requirements using three types of protocols:
ArithmeticGMW, BooleanGMW, and BMR. A Python script `geninput.py` is also
provided and used to create files that can help generate inputs and the expected
results for these examples.

### CrossTabs

This example takes two vectors of integers as inputs and computes a
crosstabulation, which is a database operation that computes, in our case sums
rather than average, by category.

The first party owns the data of each category, possibly more than one value for
one category, and the second party holds the categories. This example allows
these parties to find out the sum in each category without revealing the values
in a category. The number of categories can be set using `bins`, so the second
party's input should not exceed `bins-1`. If that's the case, then the modulo of
this number will be computed and used.

In our example, the inputs can be given directly from terminal using
`--input` or from a file by specifying the path using `--input-file`. For this
example the protocol is set as BooleanGMW and cannot be chosen.

###### Important Note :

* Exactly 2 parties are needed
* The same number of data and categories are needed.

#### Example :

```
bins = 5;
party_0 = {2, 6, 7, 9, 10, 2};
party_1 = {1, 2, 3, 4, 1, 2};

output :
Bin 0 = 0
Bin 1 = 2 + 10 = 12
Bin 2 = 6 + 2 = 8
Bin 3 = 7
Bin 4 = 9
```

#### Real Life Example :

In order to analyze the obesity risk in different age groups, authorized
researchers want to compute average BMI over anonymized health data stored at
some medical institute. The researchers themselves know only the pseudonyms of
the people in the database and their age group. The institute, on the other
hand, knows only the pseudonyms of the people and their BMI. Also, neither the
institute nor the researchers are allowed to reveal the cleartext data to anyone
else. Now, both parties can use secure cross-tabulation to privately compute the
sum of the BMIs in each age group as follows :

* The institute has two columns data:
    * `ID` : The pseudonym of each person.
    * `data` : The BMI of each person.
    
* The researchers also have two columns data :
    * `ID` : The pseudonym of each person.
    * `categories` : The age groups from `0 ... bins-1`.

The `bins` is set according to the number of age groups. To do the computation,
the `data` from the institute will be grouped and accumulated by the `categories`
from the institute. A real example with a small number of data can be pictured 
like so :

```
Institute's data
Pseudonym 0 - BMI 24
Pseudonym 1 - BMI 19
Pseudonym 2 - BMI 26
Pseudonym 3 - BMI 16
Pseudonym 4 - BMI 20
Pseudonym 5 - BMI 19

Researchers' data
Pseudonym 0 - Group 0
Pseudonym 1 - Group 1
Pseudonym 2 - Group 2
Pseudonym 3 - Group 4
Pseudonym 4 - Group 0
Pseudonym 5 - Group 2

bins = 5 (number of age groups from 0 ... 4)

Institute = {24, 19, 26, 16, 20, 19};
Researchers = {0, 1, 2, 4, 0, 2};

Result :
Group 0 = 24 + 20 = 44
Group 1 = 19
Group 2 = 26 + 19 = 45
Group 3 = 0
Group 4 = 16
```

### InnerProduct

This example takes two vectors of integers and computes the inner product (
scalar product, dot product) of these inputs. In other words, it computes the
sum of the pairwise product of their elements. This allows two parties to
compute the inner product of their inputs, without revealing the inputs
itselves.

In our example, the inputs can be given directly from terminal using
`--input` or from a file by specifying the path using `--input-file`. All three
protocols (ArithmeticGMW, BooleanGMW, BMR) are supported.

###### Important Note :

* Exactly 2 parties are needed
* The same number of elements from both parties are needed.

#### Example :

```
party_0 = {2, 3, 4};
party_1 = {1, 2, 3};

output :
Result = (2 * 1) + (3 * 2) + (4 * 3) = 20
```

### Mult3

#### Mult3 with real inputs

This example takes an integer input from three different parties and computes
the multiplication of these three inputs.

In our example, the inputs can be given directly from terminal using
`--input` or from a file by specifying the path using `--input-file`. All three
protocols (ArithmeticGMW, BooleanGMW, BMR) are supported.

###### Important Note :

* Exactly 3 parties are needed

#### Example :

```
party_0 = {2};
party_1 = {1};
party_2 = {3};

output :
Result = 6
```

#### Mult3 with shared inputs

This example takes three secret shared inputs from two parties and computes the
multiplication of these inputs.

In our example, the inputs can only be given from a file by specifying the path
using `--input-file-shared`. Random inputs and the corresponding expected result
can be generated using our Python script `geninput.py`. This example supports
ArithmeticGMW and BooleanGMW. However, each protocol needs different inputs so
that it can work properly (see Examples).

###### Important Note :

* Exactly 2 parties are needed

#### Example for ArithmeticGMW :

```
party_0 = {x0-r0, x1-r1, x2-r2};
party_1 = {r0, r1, r2};

output :
Result = x0 * x1 * x2;
```

#### Example for BooleanGMW :

```
party_0 = {x0^r0, x1^r1, x2^r2};
party_1 = {r0, r1, r2};

output :
Result = x0 ^ x1 ^ x2;
```

with `^` as XOR computation.