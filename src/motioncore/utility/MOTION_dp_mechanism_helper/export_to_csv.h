// MIT License
//
// Copyright (c) 2022 Liang Zhao
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <fstream>
#include <string>
#include <utility>  // std::pair
#include <vector>

void write_csv(std::string filename,
               std::vector<std::pair<std::string, std::vector<double>>> dataset) {
  // Make a CSV file with one or more columns of integer values
  // Each column of data is represented by the pair <column name, column data>
  //   as std::pair<std::string, std::vector<int>>
  // The dataset is represented as a vector of these columns
  // Note that all columns should be the same size

  // Create an output filestream object
  //    std::ofstream myFile(filename);

  // file pointer
  std::fstream myFile;

  // opens an existing csv file or creates a new file.
  myFile.open(filename, std::ios::out | std::ios::app);

  // Send data to the stream
  for (int i = 0; i < dataset.at(0).second.size(); ++i) {
    for (int j = 0; j < dataset.size(); ++j) {
      myFile << dataset.at(j).second.at(i);
      if (j != dataset.size() - 1) myFile << ",";  // No comma at end of line
    }
    myFile << "\n";
  }

  // Close the file
  myFile.close();
}