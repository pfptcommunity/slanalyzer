/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "src/Analyzer.h"
#include "src/UserAnalyzer.h"
#include "src/Matcher.h"
#include <getopt.h>
#include <filesystem>
#include <chrono>
#include <iostream>
#include "src/UserSafeList.h"

using namespace std;
using namespace std::chrono;

void help()
{
	cout << "Usage: slanalyzer [-h] [-s SAFELIST|BLOCKLIST ] [-u USEREXPORT ] [-o OUTPUTFILE] [SMART_SEARCH_FILES...]"
		 << endl
		 << endl
		 << "Search multiple smart search exports to determine which safe or block list entries triggered against the mail flow."
		 << endl
		 << endl
		 << "Options:"
		 << endl
		 << "-s, --safelist        (required) safelist file to use for smart search file processing"
		 << endl
		 << "-u, --userlist        (required) PPS user export, personal safe and blocked list to use for smart search file processing"
		 << endl
		 << "-o, --output          (required) annotated safelist created after smart search processing"
		 << endl
		 << "-h, --help            show this help message and exit"
		 << endl
		 << endl
		 << "Positional Arguments:"
		 << endl
		 << "SS_FILES              (required positional) one or more cloud smart search exports."
		 << endl
		 << endl;
}

void usage()
{
	cout << "Usage: slanalyzer [-h] [-s SAFELIST|BLOCKLIST ] [-u USEREXPORT ] [-o OUTPUTFILE] [SMART_SEARCH_FILES...]" << endl
		 << "Try 'slanalyzer --help' for more information." << endl;
}

int main(int argc, char* argv[])
{

	if (argc==1) {
		usage();
		exit(1);
	}

	int c;
	string safe_list;
	string user_list;
	string output_list;
	vector<string> ss_inputs;
	bool safe = false;
	bool user = false;
	bool output = false;
	bool files = false;
	static struct option long_options[] =
			{
					{("safelist"), required_argument, 0, 's'},
					{("userlist"), required_argument, 0, 'u'},
					{("output"), required_argument, 0, 'o'},
					{("help"), no_argument, 0, 'h'},
					{0, 0, 0, 0}
			};

	int option_index = 0;

	while ((c = getopt_long(argc, argv, "s:u:o:h", long_options, &option_index))!=-1) {
		switch (c) {
		case 's': safe_list = optarg;
			safe = true;
			break;
		case 'u': user_list = optarg;
			user = true;
			break;
		case 'o': output_list = optarg;
			output = true;
			break;
		case 'h': help();
			exit(0);
			break;
		case '?':
		default: usage();
			exit(1);
			break;
		}
	}

	if (optind<argc) {
		files = true;
		while (optind<argc) {
			if (!filesystem::exists(argv[optind])) {
				cerr << "Smart search file " << quoted(argv[optind]) << " doesn't exist." << endl;
				exit(1);
			}
			ss_inputs.emplace_back(argv[optind]);
			optind++;
		}
	}

	if( safe && user ){
		cerr << "Argument --safelist and --userlist can not be combined." << endl;
		exit(1);
	}

	if (safe && safe_list.empty()) {
		cerr << "Input list can not be an empty string." << endl;
		exit(1);
	}

	if (safe && !filesystem::exists(safe_list)) {
		cerr << "Input list: " << quoted(safe_list) << " doesn't exist" << endl;
		exit(1);
	}

	if (user && user_list.empty()) {
		cerr << "User list can not be an empty string." << endl;
		exit(1);
	}

	if (user && !filesystem::exists(user_list)) {
		cerr << "User list: " << quoted(user_list) << " doesn't exist" << endl;
		exit(1);
	}

	if (output && output_list.empty()) {
		cerr << "Output file can not be an empty string." << endl;
		exit(1);
	}

	filesystem::path p(output_list);
	if (filesystem::is_directory(p)) {
		cerr << "Output file is a directory: " << quoted(output_list)
			 << " please specify a filename" << endl;
		exit(1);
	}

	if (ss_inputs.empty()) {
		cerr << "Smart search files must be provided." << endl;
		exit(1);
	}

	if (!(safe || user) || !output || !files) {
		usage();
		exit(1);
	}


	std::cout << std::left << std::setw(25) << "Status" << " "
			  << std::left << std::setw(25) << "Microseconds" << " "
			  << std::setw(25) << "Seconds" << " "
			  << std::setw(25) << "Records " << " "
			  << "Filename" << std::endl;

	auto start = high_resolution_clock::now();

	if( safe ) {

		Proofpoint::SafeList safelist;
		Proofpoint::SafeList::EntryErrors entry_errors;

		safelist.Load(safe_list, entry_errors);

		// Used to collect pattern errors in the even there is a bad pattern
		Proofpoint::PatternErrors pattern_errors;

		Proofpoint::Analyzer processor(safelist, pattern_errors);

		for (const auto& file : ss_inputs) {
			processor.Process(file, safelist);
		}

		safelist.Save(output_list);

		if (!pattern_errors.empty()) {
			cerr << endl << endl << endl << "Pattern errors occurred, see the following entries in your safe or blocked list:" << endl;
			for (auto e : pattern_errors) {
				cerr << "Line: " << e.index << " Pattern: " << e.pattern << " Reason: " << e.error << endl;
			}
		}

		if (!entry_errors.empty()) {
			cerr << endl << endl << endl << "Entry errors occurred, see the following entries in your safe or blocked list:" << endl;
			for (auto e : entry_errors) {
				cerr << "Line: " << e.index << " FieldType: " << e.field_data << " MatchType: " << e.match_data << "Error: " << e.error << endl;
			}
		}
	}

	if( user ) {
		Proofpoint::UserSafeList user_safe_list;
		Proofpoint::UserSafeList::UserErrors user_errors;
		user_safe_list.Load(user_list, user_errors);

		// Used to collect pattern errors in the even there is a bad pattern
		Proofpoint::PatternErrors pattern_errors;
		Proofpoint::UserAnalyzer processor(user_safe_list,pattern_errors);

		for (const auto& file : ss_inputs) {
			processor.Process(file, user_safe_list);
		}

		user_safe_list.Save(output_list);
	}

	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop-start);
	std::cout << std::left << std::setw(25) << "Processing Completed" << " "
			  << std::left << std::setw(25) << std::to_string(duration.count()) << " "
			  << std::setw(25) << std::setprecision(2) << std::to_string((double)duration.count()/1000000) << " "
			  << std::setw(25) << std::endl;

	return 0;
}
