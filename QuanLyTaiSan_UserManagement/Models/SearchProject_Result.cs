//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace QuanLyTaiSan_UserManagement.Models
{
    using System;
    
    public partial class SearchProject_Result
    {
        public int Id { get; set; }
        public string ProjectName { get; set; }
        public Nullable<int> ManagerProject { get; set; }
        public string Address { get; set; }
        public Nullable<System.DateTime> FromDate { get; set; }
        public Nullable<System.DateTime> ToDate { get; set; }
        public Nullable<System.DateTime> CreatedDate { get; set; }
        public Nullable<System.DateTime> ModifiedDate { get; set; }
        public int Status { get; set; }
        public string FullName { get; set; }
        public string ProjectSymbol { get; set; }
        public Nullable<int> NumDevice { get; set; }
        public Nullable<int> TypeProject { get; set; }
    }
}
