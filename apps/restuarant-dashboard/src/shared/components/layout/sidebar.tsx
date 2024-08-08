import Image from "next/image";
import SideNav from "./side.nav";
import { Icons } from "../../../utils/Icon";

const Sidebar = () => {
  return (
    <div className="bg-[#111C43] fixed w-2/12">
      <div className="p-3 flex flex-col justify-around h-screen">
        <div className="w-[90%] flex flex-col items-center">
          <Image
            src={
              "https://res.cloudinary.com/difmknbax/image/upload/v1722158137/ffzteoijrcrkxlkbomel.png"
            }
            alt="profile-pic"
            width={120}
            height={120}
            className="rounded-full border-3 border-[rgb(91_111_230)]"
          />
          <h5 className="pt-3 text-2xl text-white">HyconDelivery</h5>
        </div>
        {/* sidenav */}
        <SideNav />
        <div className="flex items-center pl-3 cursor-pointer"></div>
      </div>
    </div>
  );
};

export default Sidebar;
