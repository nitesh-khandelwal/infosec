#include<bits/stdc++.h>
#include<math.h>
#include <vector>
#include <numeric>
#include <iostream>
#include <fstream>
#define C 110   //Average packet Transmission rate.(This is to be determined empirically)
#define Time_Window 20 //We are utilizing a Time Window of 10 seconds to check our connection.
#define Delta_T 1
#define alpha 5
#define CONNECTION_CLOSED -1//Defining Connection Closed Flag to denote the Closure of Connection.
int count = 0;//global count to check for termination
//Function to calculate the Vulnerability Constant V.C.
double calculateVC(int noOfPackets){
    return (noOfPackets*alpha)/(1+pow(C,alpha));
}
//Function to calculate the average of all the V.C's present until a specific instant at which we check for the connection.
float average(std::vector<float> const& v){
    if(v.empty()){
        return 0;
    }
    float average = std::accumulate(v.begin(), v.end(), 0.0) / v.size();
    return average;
}
//Implementation of our proposed DoS Detection Algorithm.
int check(int time_window, int count_threshold, double vc_threshold, double vc, std::vector <float> v)
{


	for(int i = 0; i < time_window; i++)
	{
		if(v[i] > vc_threshold)
			count++;
	}

	if(count > count_threshold)
	{
		std::cout << "connection closed"<<"\n";
		return CONNECTION_CLOSED;
	}
	else
	{
		if(v.size() != time_window)
			v.push_back(vc);
		else
		{
			v.erase(v.begin());
			v.push_back(vc);
		}
		std::cout<<"COUNT::"<<count<<"V.C::"<<vc<<" V.C Threshold::"<<vc_threshold<<"\n";
		count =0;
	}
}

int main()
{
    std::ofstream myfile;
    int noOfPackets;

    myfile.open ("C:\\Users\\user\\OneDrive\\Desktop\\DataValues.txt");
	std::vector <float> v;
    /*At every Time Stamp T.S we calculate the Vulnerability Constant (V.C) and check if the Connection is to be closed
    as per the proposed Algorithm.
    */
    for(int i=0;i<Time_Window;i=i+Delta_T){
    std::cout<<"Enter the Number of packets sent in interval "<<i<<" th"<<"\n";
    std::cin>>noOfPackets;
    myfile << noOfPackets<<","<<calculateVC(noOfPackets)<<","<<average(v)<<"\n";
    v.push_back(calculateVC(noOfPackets));
    if(check(v.size(),10, average(v), calculateVC(noOfPackets), v)== CONNECTION_CLOSED)
        break;
}
    myfile.close();

	return 0;
}
