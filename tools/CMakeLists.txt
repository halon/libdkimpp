ADD_EXECUTABLE(dkimtool src/main.cpp)
TARGET_LINK_LIBRARIES(dkimtool
	dkim++
)
INCLUDE_DIRECTORIES(
	../src/
)
