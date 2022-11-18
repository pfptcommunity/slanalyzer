/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */

#include "UserList.h"
#include "CsvParser.h"
#include <iostream>
#include <iomanip>
#include <numeric>
#include <chrono>
#include "Utils.h"

Proofpoint::UserList::UserList() :address_count(0) {}

void Proofpoint::UserList::Load(const std::string& user_file, UserErrors& entry_errors)
{
	address_count = 0;
	std::size_t count = 0;
	using std::chrono::high_resolution_clock;
	using std::chrono::microseconds;
	auto start = high_resolution_clock::now();
	std::ifstream f(user_file);
	csv::CsvParser parser(f);
	csv::HeaderMap header_map;
	csv::HeaderList required_headers{
			"mailLocalAddress",
			"safelist",
			"blocklist",
			"givenName",
			"sn",
			"mail"};

	// Validate there are headers we are interested in...
	csv::HeaderIndex header_index = parser.FindHeader(required_headers, header_map);

	if (header_index!=-1)
		for (const auto& row : parser) {
			user_list.emplace_back();
			user_list.back().givenName = row[header_map.find("givenName")->second];
			user_list.back().sn = row[header_map.find("sn")->second];
			user_list.back().mail = row[header_map.find("mail")->second];
			address_count++;
			for (auto proxy_address : Utils::split(row[header_map.find("mailLocalAddress")->second], ';')) {
				user_list.back().proxy_addresses.emplace_back(proxy_address);
				address_count++;
			}
			for (auto safe_entry : Utils::split(row[header_map.find("safelist")->second], ';')) {
				user_list.back().safe.emplace_back(safe_entry);
			}
			for (auto safe_entry : Utils::split(row[header_map.find("blocklist")->second], ';')) {
				user_list.back().block.emplace_back(safe_entry);
			}
			user_list.back().safe_count = 0;
			user_list.back().block_count = 0;
			count++;
		}
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop-start);
	std::cout << std::left << std::setw(25) << "User Load Completed" << " "
			  << std::left << std::setw(25) << std::to_string(duration.count()) << " "
			  << std::setw(25) << std::setprecision(2) << std::to_string((double)duration.count()/1000000) << " "
			  << std::setw(25) << count << " "
			  << user_file << std::endl;
}

void Proofpoint::UserList::Save(const std::string& user_file)
{
	std::size_t count = 0;
	using std::chrono::high_resolution_clock;
	using std::chrono::microseconds;
	auto start = high_resolution_clock::now();
	std::ios_base::sync_with_stdio(false);
	std::ofstream f(user_file);
	f  << "\"" << "givenName"
	  << "\",\"" << "sn"
	  << "\",\"" << "mail"
	  << "\",\"" << "mailLocalAddress"
	  << "\",\"" << "safelist"
	  << "\",\"" << "blocklist"
	  << "\",\"" << "safe_count"
	  << "\",\"" << "block_count" <<"\"\r\n";

	auto concat = [](const std::string& a, const std::string& b) -> std::string { return a + (a.size() > 0 ? ";" : "") + b;};

	for (const auto& user : user_list) {
		f << "\"" << user.givenName
		  << "\",\"" << user.sn
		  << "\",\"" << user.mail
		  << "\",\"" << std::accumulate(user.proxy_addresses.begin(), user.proxy_addresses.end(), std::string(), concat )
		  << "\",\"" << std::accumulate(user.safe.begin(), user.safe.end(), std::string(), concat)
		  << "\",\"" << std::accumulate(user.block.begin(), user.block.end(), std::string(), concat)
		  << "\",\"" << user.safe_count
		  << "\",\"" << user.block_count << "\"\r\n";
		count++;
	}

	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop-start);
	std::ios_base::sync_with_stdio(true);
	std::cout << std::left << std::setw(25) << "SL Save Completed" << " "
			  << std::left << std::setw(25) << std::to_string(duration.count()) << " "
			  << std::setw(25) << std::setprecision(2) << std::to_string((double)duration.count()/1000000) << " "
			  << std::setw(25) << count << " "
			  << user_file << std::endl;
}
