﻿//------------------------------------------------------------------------------
// <auto-generated>
//     這個程式碼是由範本產生。
//
//     對這個檔案進行手動變更可能導致您的應用程式產生未預期的行為。
//     如果重新產生程式碼，將會覆寫對這個檔案的手動變更。
// </auto-generated>
//------------------------------------------------------------------------------

namespace DBHelper
{
    using System;
    using System.Data.Entity;
    using System.Data.Entity.Infrastructure;
    
    public partial class TWIDAPPEntities : DbContext
    {
        public TWIDAPPEntities()
            : base("name=TWIDAPPEntities")
        {
        }
    
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            throw new UnintentionalCodeFirstException();
        }
    
        public virtual DbSet<ActionLog> ActionLog { get; set; }
        public virtual DbSet<VerifyType> VerifyType { get; set; }
        public virtual DbSet<AspNetUsers> AspNetUsers { get; set; }
        public virtual DbSet<Verification> Verification { get; set; }
        public virtual DbSet<MOICASHA256> MOICASHA256 { get; set; }
        public virtual DbSet<MOICASN> MOICASN { get; set; }
    }
}
