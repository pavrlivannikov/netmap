import workstation from "/icons/workstation.svg";
import server from "/icons/server.svg";
import router from "/icons/router.svg";
import switchIcon from "/icons/switch.svg";
import printer from "/icons/printer.svg";
import camera from "/icons/camera.svg";
import iot from "/icons/iot.svg";
import unknown from "/icons/unknown.svg";

const icons = {
  workstation,
  server,
  router,
  switch: switchIcon,
  printer,
  camera,
  iot,
  unknown,
};

export function getIconForType(type) {
  return icons[type] || icons.unknown;
}

export default icons;
