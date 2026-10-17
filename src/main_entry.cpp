//  main_entry.cpp —— 控制台入口胶水：把标准 main 转发到 cli_main
int cli_main(int argc, char** argv);

extern "C" int main(int argc, char** argv) { return cli_main(argc, argv); }
