# CyberShield AI ProGuard rules
-keepattributes Signature, InnerClasses, EnclosingMethod
-keep class com.cybershieldai.data.model.** { *; }
-keep class com.cybershieldai.network.** { *; }
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}
-dontwarn okhttp3.**
-dontwarn retrofit2.**
