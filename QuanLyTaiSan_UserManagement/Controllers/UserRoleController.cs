using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using QuanLyTaiSan_UserManagement.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.SqlClient;
using QuanLyTaiSan_UserManagement.Attribute;
using QuanLyTaiSan_UserManagement.Common;

namespace QuanLyTaiSan_UserManagement.Controllers
{

    public class UserRoleController : Controller
    {
        QuanLyTaiSanCtyEntities data = new QuanLyTaiSanCtyEntities();
        Encryptor encr = new Encryptor();
        [HasCredential(RoleID = "VIEW_USER")]
        public ActionResult UserIndex()
        {
            var dao = new UserDao();
            var users = data.UserLogins.Where(x => x.IsDeleted == false).ToList();
            var userRole = new List<InformationUser>();
            foreach (var item in users)
            {
                //  var firstRoleId = data.UserLogins.Where(x => x.);
                //  var firstRoleId = data.UserLogins.FirstOrDefault()?.GroupID;
                if (!string.IsNullOrEmpty(item.GroupID))
                {
                    var NameGrRole = data.UserGroups.Where(x => x.ID == item.GroupID).Select(x => x.Name).First();
                    userRole.Add(new InformationUser()
                    {
                        Id = item.Id,
                        Username = item.UserName,
                        RoleGroupID = item.GroupID,
                        RoleGroupName = NameGrRole,
                        FullName = item.FullName,

                    });
                }
                else
                {
                    userRole.Add(new InformationUser()
                    {
                        Id = item.Id,
                        Username = item.UserName,
                        RoleGroupID = item.GroupID,
                        RoleGroupName = "Chưa được phân quyền",
                        FullName = item.FullName,

                    });
                }
            }
            ViewData["Department"] = data.ProjectDKCs.Where(x => x.IsDeleted == false).ToList();
            ViewData["Users"] = userRole;
            ViewData["Roles"] = data.UserGroups.ToList();
            return View();
        }

        [HttpPost]
        [ValidateInput(false)]
        //[ValidateAntiForgeryToken]
        [HasCredential(RoleID = "ADD_USER")]
        public ActionResult RegisterUser(string FullName, string Role, string Username, string Password,string Department, string TypeAcc)
        {
            var dao = new UserDao();
            var result = dao.UpdateRoleUser(FullName, Username, Role, encr.Encrypt(Password, Username, true), Department, TypeAcc);
            return Json(result, JsonRequestBehavior.AllowGet);
        }

        [HttpGet]
        [HasCredential(RoleID = "CHANGE_INFO_USER")]
        public JsonResult GetInfoAccount(string userId)
        {
            data.Configuration.ProxyCreationEnabled = false;
            //  bool result = true;
            var u = userId.Trim();
            var lstInfo = data.UserLogins.Where(x => x.UserName == u).FirstOrDefault();
            var _pass = encr.Decrypt(lstInfo.PassWord.Trim(), lstInfo.UserName.Trim(), true);
            List<string> Pass1 = new List<string>(_pass.Split(new string[] { "[|]" }, StringSplitOptions.None));
            lstInfo.PassWord = Pass1[0];
            return Json(new { lstInfo }, JsonRequestBehavior.AllowGet);
        }

        [HttpPost]
        [HasCredential(RoleID = "CHANGE_USER_GROUP")]
        public JsonResult ChangeRoleByUserId(int ID, string FullName, string Username, string Role, string Password, string Department, string TypeAcc)
        {
            // bool result = true;
            var dao = new UserDao();
            var result = dao.UpdateRole(ID, FullName, Username, Role, encr.Encrypt(Password, Username, true), Department, TypeAcc);
            return Json(result);
        }


        [HttpPost]
        [HasCredential(RoleID = "DELETE_USER")]
        public JsonResult DeleteUser(int userId)
        {
            var dao = new UserDao();
            var result = dao.DeleteRoleUser(userId);
            return Json(result);
        }
    }
}