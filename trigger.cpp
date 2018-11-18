#include <string>
#include <sstream>
#include <vector>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include "pcapsipdump_lib.h"
#include "trigger.h"

using namespace std;

template <typename T>
class makevec {
public:
	typedef makevec<T> my_type;
	my_type& operator<< (const T& val) {
		data_.push_back(val);
		return *this;
	}
	operator std::vector<T>() const {
		return data_;
	}
private:
	std::vector<T> data_;
};

void Trigger::init(void) {
    Trigger::byname["open"] = &Trigger::open;
    Trigger::byname["close"] = &Trigger::close;
};

void Trigger::add(const string s) {
	string trigger, action, param;
	stringstream ss(s);
	getline(ss, trigger, ':');
	getline(ss, action, ':');
	getline(ss, param, ':');
	if (!(Trigger::byname.count(trigger))) {
		cout << "ERROR: Can't make sense of trigger '" << s <<
			"': Not a valid trigger condition '" << trigger << "'." << endl;
		exit(2);
	}
	if (action == "mv") {
		vector <string> t = makevec<string>() << "/bin/mv" << "%." << param;
		Trigger::byname[trigger]->push_back(t);
	}
	else if (action == "sh") {
		vector <string> t = makevec<string>() << "/bin/sh" << "-c" << param;
		Trigger::byname[trigger]->push_back(t);
	}
	else if (action == "exec") {
		istringstream ss(param);
		vector <string> split_param;
		while (1) {
			string elem;
			ss >> elem;
			if (!ss) { break; };
			split_param.push_back(elem);
		};
		Trigger::byname[trigger]->push_back(split_param);
	}
	else {
		cout << "ERROR: Can't make sense of trigger '" << s <<
			"': Unrecognized action: '" << action << "'" << endl;
	};
	if (Trigger::verbosity >= 2) {
		cout << "Added '" << trigger << "' trigger:";
		vector <string> *t = &Trigger::byname[trigger]->back();
		for (vector <string>::iterator i = t->begin(); i != t->end(); i++) {
			cout << ' ' << *i;
		}
		cout << endl;
	}
}

void Trigger::trigger(const vector <vector <string> > *t_const,
	const std::string & fn,
	const std::string & from,
	const std::string & to,
	const std::string & callid,
	const time_t time) {
	vector <vector <string> > t = *t_const;
	for (vector <vector <string> >::iterator i = t.begin(); i != t.end(); i++) {
		pid_t pid = fork();
		if (pid == 0) {
			// child process
			vector <const char*> argv;
			vector<std::string> argvstr;
			for (vector <string>::iterator j = i->begin(); j != i->end(); j++) {
				const char *s = "";
				const char *js = j->c_str();
				if (*j == "%.") {
					s = fn.c_str();
				}
				else if (strchr(js, '%')) {
					char tmp[1024];
					expand_dir_template(tmp, 1024, js, from.c_str(), to.c_str(), callid.c_str(), time);
					argvstr.push_back(tmp);
					s = argvstr[argvstr.size() - 1].c_str();
				}
				else {
					s = js;
				}
				argv.push_back(s);
			}
			if (Trigger::verbosity >= 2) {
				cout << "Executing trigger:";
				for (vector <const char*>::iterator j = argv.begin(); j != argv.end(); j++) {
					cout << ' ' << *j;
				}
				cout << endl;
			}
			argv.push_back(NULL);
			execv(argv[0], (char* const*)&argv[0]);
			cout << "Warning: Can't execv()" << endl;
		}
		else if (pid < 0) {
			cout << "Warning: Can't fork()" << endl;
		}
	}
}

vector <vector <string> > Trigger::open;
vector <vector <string> > Trigger::close;
map <string, vector <vector <string> >* > Trigger::byname;
int Trigger::verbosity = 0;

Trigger trigger;
