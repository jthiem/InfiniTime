#pragma once

#include "displayapp/DisplayApp.h"
#include "displayapp/screens/Screen.h"
#include "displayapp/Controllers.h"
#include "Symbols.h"
#include <lvgl/lvgl.h>

namespace Pinetime {
  namespace Applications {
    namespace Screens {
      class TOTP : public Screen {
      public:
        TOTP();
        ~TOTP() override;
        void Refresh() override;

      private:
        lv_obj_t* title = nullptr;
        lv_obj_t* labelCode = nullptr;
        lv_obj_t* labelTimer = nullptr;
        lv_task_t* taskRefresh = nullptr;
      };
    }

    template <>
    struct AppTraits<Apps::TOTP> {
      static constexpr Apps app = Apps::TOTP;
      static constexpr const char* icon = Screens::Symbols::lock;

      static Screens::Screen* Create(AppControllers& controllers) {
        return new Screens::TOTP();
      }

      static bool IsAvailable(Pinetime::Controllers::FS& /*filesystem*/) {
        return true;
      }
    };
  }
}