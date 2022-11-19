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

Proofpoint::UserList::UserList() :address_count(0), safe_count(0), block_count(0) {}

void Proofpoint::UserList::Load(const std::string& user_file, UserErrors& entry_errors)
{
	address_count = 0;
	std::size_t count = 0;
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
			entries.emplace_back();
			entries.back().givenName = row[header_map.find("givenName")->second];
			entries.back().sn = row[header_map.find("sn")->second];
			entries.back().mail = row[header_map.find("mail")->second];
			address_count++;
			for (auto proxy_address : Utils::split(row[header_map.find("mailLocalAddress")->second], ';')) {
				entries.back().proxy_addresses.emplace_back(proxy_address);
				address_count++;
			}
			for (auto safe_entry : Utils::split(row[header_map.find("safelist")->second], ';')) {
				entries.back().safe.emplace_back(std::string(safe_entry));
				safe_count++;
			}
			for (auto block_entry : Utils::split(row[header_map.find("blocklist")->second], ';')) {
				entries.back().block.emplace_back(std::string(block_entry));
				block_count++;
			}
			count++;
		}
}

void Proofpoint::UserList::Save(const std::string& user_file)
{
	std::size_t count = 0;
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

	auto concat1 = [](const std::string& a, const std::string& b) -> std::string { return a + (a.size() > 0 ? ";" : "") + b;};
	//auto concat2 = [](const UserList::Entry::ListItem& a, const UserList::Entry::ListItem& b) -> UserList::Entry::ListItem { return a.pattern + (a.pattern.size() > 0 ? ";" : "") + b.pattern;};

	for (const auto& user : entries) {
		f << "\"" << user.givenName
		  << "\",\"" << user.sn
		  << "\",\"" << user.mail
		  << "\",\"" << std::accumulate(user.proxy_addresses.begin(), user.proxy_addresses.end(), std::string(), concat1 )
		  //<< "\",\"" << std::accumulate(user.safe.begin(), user.safe.end(), std::string(), concat2)
		 // << "\",\"" << std::accumulate(user.block.begin(), user.block.end(), std::string(), concat2)
		 << "\"\r\n";
		count++;
	}
}
