#include "displayapp/screens/TOTP.h"
#include <lvgl/lvgl.h>

using namespace Pinetime::Applications::Screens;


TOTP::TOTP() {
  title = lv_label_create(lv_scr_act(), nullptr);
  lv_label_set_text_static(title, "Hello World");
  lv_obj_align(title, nullptr, LV_ALIGN_IN_TOP_MID, 0, 20);

  labelTimer = lv_label_create(lv_scr_act(), nullptr);
  lv_label_set_text_static(labelTimer, "00");
  lv_obj_align(labelTimer, nullptr, LV_ALIGN_CENTER, 0, 0);

  taskRefresh = lv_task_create(RefreshTaskCallback, 1000, LV_TASK_PRIO_MID, this);
  Refresh();
}

TOTP::~TOTP() {
  if (taskRefresh) {
    lv_task_del(taskRefresh);
  }
  lv_obj_clean(lv_scr_act());
}

void TOTP::Refresh() {
  const int seconds = static_cast<int>((lv_tick_get() / 1000ull) % 30ull);
  lv_label_set_text_fmt(labelTimer, "%02d", seconds);
  lv_obj_align(labelTimer, nullptr, LV_ALIGN_CENTER, 0, 0);
}