//
// Created by liangzhao on 27.05.22.
//

#pragma once

#include <string>
#include <fstream>
#include <vector>
#include <utility> // std::pair

void write_csv(std::string filename, std::vector<std::pair<std::string, std::vector<double>>> dataset){
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

//    // Send column names to the stream
//    for(int j = 0; j < dataset.size(); ++j)
//    {
//        myFile << dataset.at(j).first;
//        if(j != dataset.size() - 1) myFile << ","; // No comma at end of line
//    }
//    myFile << "\n";

    // Send data to the stream
    for(int i = 0; i < dataset.at(0).second.size(); ++i)
    {
        for(int j = 0; j < dataset.size(); ++j)
        {
            myFile << dataset.at(j).second.at(i);
            if(j != dataset.size() - 1) myFile << ","; // No comma at end of line
        }
        myFile << "\n";
    }

    // Close the file
    myFile.close();
}