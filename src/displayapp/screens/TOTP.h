#pragma once

#include "displayapp/DisplayApp.h"
#include "displayapp/screens/Screen.h"
#include "displayapp/Controllers.h"
#include "Symbols.h"

namespace Pinetime {
  namespace Applications {
    namespace Screens {
      class TOTP : public Screen {
      public:
        TOTP();
        ~TOTP() override;
      };
    }

    template <>
    struct AppTraits<Apps::TOTP> {
      static constexpr Apps app = Apps::TOTP;
      static constexpr const char* icon = Screens::Symbols::tachometer;

      static Screens::Screen* Create(AppControllers& controllers) {
        return new Screens::TOTP();
      }
    };
  }
}