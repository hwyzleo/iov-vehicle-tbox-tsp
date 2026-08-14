// TBOX-TSP-DSN-CR-005 §9.1 / CR-009: 最小入口（唯一生命周期路径）。
// main() 仅构造并运行 TspApplication，不解析配置、不初始化日志、不注册信号、
// 不维护运行循环——全部由 hwyz::Application 编排。
// CR-009: main_legacy.cpp 与 TSP_USE_FRAMEWORK_APPLICATION 开关已删除。

#include "tsp_application.h"

int main(int argc, char* argv[]) {
    tbox::tsp::TspApplication app;
    return app.run(argc, argv);
}
