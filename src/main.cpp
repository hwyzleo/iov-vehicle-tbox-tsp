// TBOX-TSP-DSN-CR-005 §9.1: 最小入口。
// main() 仅构造并运行 TspApplication，不解析配置、不初始化日志、不注册信号、
// 不维护运行循环——全部由 hwyz::Application 编排。
//
// 当 TSP_USE_FRAMEWORK_APPLICATION=OFF 时编译 main_legacy.cpp（旧式手写生命周期，
// 回滚验证用，验收后删除本开关与 main_legacy.cpp）。

#include "tsp_application.h"

int main(int argc, char* argv[]) {
    tbox::tsp::TspApplication app;
    return app.run(argc, argv);
}
