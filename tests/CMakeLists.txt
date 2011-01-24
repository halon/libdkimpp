INCLUDE(FindCppUnit.cmake)

FILE(GLOB_RECURSE UnitTestSrc "src/*Test.cpp" )

ADD_EXECUTABLE(UnitTest src/testMain.cpp ${UnitTestSrc})

FOREACH(test ${UnitTestSrc})
    GET_FILENAME_COMPONENT(TestName ${test} NAME_WE)
    MESSAGE(STATUS "Adding Test ${TestName}")
    ADD_TEST(${TestName} UnitTest ${TestName})
ENDFOREACH(test)

TARGET_LINK_LIBRARIES(UnitTest
    ${CPPUNIT_LDFLAGS}
	dkim++
)

INCLUDE_DIRECTORIES(
    ${CPPUNIT_INCLUDE_DIRS}
)
