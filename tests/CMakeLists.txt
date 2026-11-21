add_executable(dfm_fd_query_check fd_query.cpp)
target_link_libraries(dfm_fd_query_check PRIVATE enkernel::sdk)
target_compile_options(dfm_fd_query_check PRIVATE -Wall -Wextra -Werror)
