# NetLurker keeps no reflection-based plumbing of its own: the JSON layer uses
# org.json explicitly and no model is deserialized by field name, so the default
# Android optimisation rules are enough. Only the Compose/tooling keeps are added.

-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# org.json ships in the framework; keep its API surface reachable.
-dontwarn org.json.**

# TrafficStats / ConnectivityManager are called directly, never reflected on.
-dontwarn android.net.**
