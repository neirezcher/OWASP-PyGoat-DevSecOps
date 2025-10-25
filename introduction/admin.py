from django.contrib import admin

from .models import (
    FAANG, AFAdmin,Info, AFSessionID,CSRFUserTbl, CFUser,
    Login, Comments, AuthLogin, OTP, Tickits, SQLLabTable, Blogs
)
# Register your models here.
admin.site.register(FAANG)
admin.site.register(Info)
admin.site.register(Login)
admin.site.register(AuthLogin)
admin.site.register(Comments)
admin.site.register(OTP)
admin.site.register(Tickits)
admin.site.register(CFUser)
admin.site.register(AFAdmin)
admin.site.register(AFSessionID)
admin.site.register(CSRFUserTbl)
admin.site.register(SQLLabTable)
admin.site.register(Blogs)