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
    
    public partial class SearchDeviceSparePartHistory_Result
    {
        public int Id { get; set; }
        public Nullable<int> SparePartId { get; set; }
        public Nullable<int> NumSparePart { get; set; }
        public string TransType { get; set; }
        public Nullable<System.DateTime> DateAdded { get; set; }
        public string Notes { get; set; }
        public Nullable<System.DateTime> CreateDate { get; set; }
        public string CreateUser { get; set; }
        public Nullable<int> Isdelete { get; set; }
        public Nullable<decimal> Amount { get; set; }
        public string SparePartName { get; set; }
        public string Amountfomat { get; set; }
        public string TypeName { get; set; }
        public string NumSparePartfomat { get; set; }
    }
}