#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>

int main( int argc, char **argv) {
	if (argc > 1)
	{
		CppUnit::TextUi::TestRunner runner;
		CppUnit::TestFactoryRegistry &registry = CppUnit::TestFactoryRegistry::getRegistry(argv[1]);
		runner.addTest( registry.makeTest() );
		int a = runner.run();
		return !a;
	}
	return 1;
} 
