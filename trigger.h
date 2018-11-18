#include <string>
#include <vector>
#include <map>

using namespace std;

class Trigger {
public:
	static vector <vector <string> > open;
	static vector <vector <string> > close;
	static map <string, vector <vector <string> >* > byname;
	static int verbosity;
	// pseudo-constructor to initialize static members
	static void init(void);
	static void add(const string s);
	static void trigger(const vector <vector <string> > *t,
		const std::string & fn,
		const std::string & from,
		const std::string & to,
		const std::string & callid,
		const time_t time);
};

extern Trigger trigger;
