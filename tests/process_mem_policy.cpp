#include "../process_mem_policy.h"
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
static void check(bool result, const char* label) {
    if (!result) { std::fprintf(stderr, "FAIL: %s\n", label); std::exit(1); }
}
int main() {
    const auto allowed=[](unsigned uid) {
        return dfm_sensor_systemui_policy(true,true,uid,true,true,
            DFM_SYSTEMUI_NAME,DFM_APP_PROCESS64);
    };
    check(allowed(1000)&&allowed(10248)&&allowed(1010248),"no fixed OEM/user SystemUI UID");
    check(!dfm_sensor_systemui_policy(true,true,10248,false,true,DFM_SYSTEMUI_NAME,DFM_APP_PROCESS64),"spoofed process name without root delegation denied");
    check(!dfm_sensor_systemui_policy(false,true,10248,true,true,DFM_SYSTEMUI_NAME,DFM_APP_PROCESS64),"nested user namespace denied");
    check(!dfm_sensor_systemui_policy(true,false,10248,true,true,DFM_SYSTEMUI_NAME,DFM_APP_PROCESS64),"mismatched credentials denied");
    check(!dfm_sensor_systemui_policy(true,true,10248,true,false,DFM_SYSTEMUI_NAME,DFM_APP_PROCESS64),"untrusted executable denied");
    for(const char* name:{"com.android.systemui:worker","com.android.systemui.extra","ndroid.systemui","com.android.settings",""})
        check(!dfm_sensor_systemui_policy(true,true,10248,true,true,name,DFM_APP_PROCESS64),"exact package/process name required");
    check(!dfm_sensor_systemui_policy(true,true,10248,true,true,DFM_SYSTEMUI_NAME,"/data/local/tmp/app_process64"),"copied executable path denied");
    check(!dfm_sensor_systemui_policy(true,true,10248,true,true,nullptr,DFM_APP_PROCESS64),"missing identity denied");
    check(!allowed(0),"root handled by the existing root path");
    std::puts("PASS: SystemUI role policy and negative delegation/identity cases (host only)");
}
