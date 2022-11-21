/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */

#include "GlobalAnalyzer.h"
#include "CsvParser.h"
#include <chrono>
#include "re2/re2.h"
#include "Utils.h"

void Proofpoint::GlobalAnalyzer::Load(const GlobalList& safelist, PatternErrors<std::size_t>& pattern_errors)
{
	for ( auto sle = safelist.begin() ; sle != safelist.end() ; sle++ ) {
		std::size_t index = std::distance(safelist.begin(),sle);
		switch (sle->field_type) {
		case GlobalList::FieldType::IP: ip.Add(sle->match_type, sle->pattern, index, pattern_errors);
			break;
		case GlobalList::FieldType::HOST: host.Add(sle->match_type, sle->pattern, index, pattern_errors);
			break;
		case GlobalList::FieldType::HELO: helo.Add(sle->match_type, sle->pattern, index, pattern_errors);
			break;
		case GlobalList::FieldType::FROM: from.Add(sle->match_type, sle->pattern, index, pattern_errors);
			break;
		case GlobalList::FieldType::HFROM: hfrom.Add(sle->match_type, sle->pattern, index, pattern_errors);
			break;
		case GlobalList::FieldType::RCPT: rcpt.Add(sle->match_type, sle->pattern, index, pattern_errors);
			break;
		case GlobalList::FieldType::UNKNOWN: break;
		}
	}
}
std::size_t Proofpoint::GlobalAnalyzer::Process(const std::string& ss_file, GlobalList& safelist, std::size_t& records_processed)
{
	csv::HeaderIndex header_index;
	std::ifstream f(ss_file);
	csv::CsvParser parser(f);
	re2::StringPiece matches[2];
	RE2 hfrom_addr_only(R"(<?\s*([a-zA-Z0-9.!#$%&’*+\/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)\s*>?\s*(?:;|$))");
	RE2 inbound_check(R"(\bdefault_inbound\b)");

	csv::HeaderMap header_map;
	csv::HeaderList required_headers{"Policy_Route",
			"Sender_IP_Address",
			"Sender_Host",
			"HELO",
			"Header_From",
			"Sender",
			"Recipients"};

	// Validate there are headers we are interested in...
	header_index = parser.FindHeader(required_headers, header_map);

	//std::cout << std::setw(35) << "Highest Index" << " " << std::setw(25) << header_index << std::endl;
	// std::multimap is useful for CSVs where there may be duplicate headers.
	//for (auto i = header_map.begin(); i!= header_map.end(); i++){
	//	std::cout << std::setw(35) << i->first << " " << std::setw(25) << i->second  << " " << header_map.count(i->first) << std::endl;
	//}

	if( header_index > -1 )
 	for (auto& row : parser){
		bool inbound = RE2::PartialMatch(row[header_map.find("Policy_Route")->second], inbound_check);
		ip.Match(inbound, row[header_map.find("Sender_IP_Address")->second], safelist.entries);
		host.Match(inbound, row[header_map.find("Sender_Host")->second], safelist.entries);
		helo.Match(inbound, row[header_map.find("HELO")->second], safelist.entries);
		// This single call has large impact on processing. Since we need to perform header from "address only"
		hfrom.Match(inbound, (hfrom_addr_only.Match(row[header_map.find("Header_From")->second], 0,
				row[header_map.find("Header_From")->second].length(), RE2::UNANCHORED, matches, 2))
				? matches[1].ToString() : row[header_map.find("Header_From")->second], safelist.entries);
		from.Match(inbound, row[header_map.find("Sender")->second], safelist.entries);
		rcpt.Match(inbound, row[header_map.find("Recipients")->second], safelist.entries);
		records_processed++;
	}
	return header_index;
}
