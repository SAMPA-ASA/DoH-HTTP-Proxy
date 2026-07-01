<div align="right" dir="rtl">

# ساختار فایل `main.py`

این فایل نقشه‌ی اصلی برنامه است و تقریباً تمام منطق اجرایی پروژه را در خودش نگه می‌دارد. برای کسی که می‌خواهد روی پروژه
کار کند، شناخت این فایل مهم‌ترین نقطه‌ی شروع است.

## تصویر کلی

فایل `main.py` فقط یک entry point ساده نیست. این فایل هم‌زمان چند نقش را انجام می‌دهد:

<ul dir="rtl" align="right">
  <li>تعریف تنظیمات و state برنامه</li>
  <li>خواندن و ذخیره‌سازی config</li>
  <li>مدیریت resolve دامنه‌ها از طریق DoH</li>
  <li>مدیریت cache و گزارش‌ها</li>
  <li>پیاده‌سازی پروکسی محلی HTTP/HTTPS</li>
  <li>اتصال به upstream proxy و DoH proxy</li>
  <li>مدیریت فایل <code>hosts</code> ویندوز</li>
  <li>نمایش منوی تعاملی</li>
  <li>اجرای برنامه در حالت CLI یا interactive</li>
</ul>

## جریان اجرای برنامه

جریان اصلی از `main()` شروع می‌شود:

1. آرگومان‌های خط فرمان با `build_arg_parser()` ساخته و parse می‌شوند.
2. اگر `--config-file` داده شده باشد، تنظیمات از فایل بارگذاری می‌شود. این گزینه در عمل یک فلگ داخلی و hidden است و    
   بیشتر برای اجرای مجدد برنامه با سطح دسترسی بالاتر استفاده می‌شود، نه به‌عنوان ورودی عادی کاربر.
3. تنظیمات نهایی با `build_startup_config_from_namespace()` ساخته می‌شوند.
4. تنظیمات پایدار با `save_persistent_startup_config()` ذخیره می‌شوند.
5. اگر ورودی و خروجی استاندارد هر دو TTY باشند و برنامه با `--config-file` اجرا نشده باشد، منوی تعاملی با    
   `run_interactive_menu()` نمایش داده می‌شود.
6. در غیر این صورت `start_proxy_session()` اجرا می‌شود.
7. اگر شروع proxy به‌خاطر اشغال بودن port یا هر `OSError` دیگری شکست بخورد، `main()` خطا را مدیریت می‌کند و پیغام خطا
   را    
   چاپ میکند.

## بخش‌های اصلی

### 1) Utility و helperها

این بخش در ابتدای فایل قرار دارد و توابع پایه را نگه می‌دارد:

<ul dir="rtl" align="right">
  <li><code>enable_ansi_colors()</code> - پشتیبانی رنگی خروجی ترمینال را فعال می‌کند.</li>
  <li><code>normalize_host()</code> - نام میزبان را نرمال‌سازی و تمیز می‌کند.</li>
  <li><code>is_ip_literal()</code> - تشخیص می‌دهد ورودی یک IP مستقیم است یا نه.</li>
  <li><code>family_for_ip()</code> - family مناسب سوکت را بر اساس IP برمی‌گرداند.</li>
  <li><code>is_benign_socket_disconnect()</code> - قطع‌های بی‌خطر سوکت را تشخیص می‌دهد.</li>
  <li><code>format_byte_count()</code> - تعداد بایت را به قالب قابل‌خواندن تبدیل می‌کند.</li>
</ul>

این helperها برای تمیز کردن ورودی‌ها، تشخیص IP literal، format خروجی و کنترل رفتار socket استفاده می‌شوند.

### 2) آمار و نمایش وضعیت

این بخش برای نمایش وضعیت لحظه‌ای برنامه است:

<ul dir="rtl" align="right">
  <li><code>TrafficStats</code> - آمار sent/received، تعداد requestها و وضعیت ترافیک proxy را نگه می‌دارد.</li>
  <li><code>build_proxy_session_lines()</code> - خطوط متنی وضعیت session را آماده می‌کند.</li>
  <li><code>render_proxy_session_screen()</code> - صفحه وضعیت proxy را رندر و نمایش می‌دهد.</li>
</ul>

وظیفه‌ی این قسمت جمع‌کردن آمار sent/received و رندر کردن صفحه‌ی وضعیت پروکسی است.

### 3) ذخیره‌سازی resolveها و cache

این قسمت مسئول نگهداری داده‌های مرتبط با resolve دامنه‌هاست:

<ul dir="rtl" align="right">
  <li><code>ResolutionLog</code> - لاگ resolveهای انجام‌شده و نتیجه هر تلاش را ثبت می‌کند.</li>
  <li><code>OptimizedDNSCache</code> - cache اصلی برای نگه‌داری IPهای پیشنهادی و hostهای دیده‌شده است.</li>
  <li><code>_OptimizedDNSCacheEntry</code> - رکورد داخلی cache برای TTL و لیست addressها است.</li>
  <li><code>OptimizeDNSReportStore</code> - گزارش JSON مربوط به Optimize DNS را می‌خواند و می‌نویسد.</li>
  <li><code>OptimizeDNSRefreshService</code> - عملیات refresh دوره‌ای cache و گزارش Optimize DNS را اجرا می‌کند.</li>
</ul>

کار این بخش‌ها:

<ul dir="rtl" align="right">
  <li>ثبت خروجی resolve شده در فایل</li>
  <li>نگهداری cache برای IPهای مناسب‌تر</li>
  <li>تولید گزارش JSON برای Optimize DNS</li>
  <li>اجرای refresh پس‌زمینه برای به‌روزرسانی IPهای پیشنهادی</li>
</ul>

### 4) مدل‌های داده

این dataclassها داده‌های ساختاری برنامه را نگه می‌دارند:

<ul dir="rtl" align="right">
  <li><code>StartupConfig</code> - همه تنظیمات اولیه و runtime برنامه را در یک dataclass نگه می‌دارد.</li>
  <li><code>HostsEntry</code> - یک رکورد parsed از فایل <code>hosts</code> را با IP و دامنه‌ها نگه می‌دارد.</li>
  <li><code>EmergencyResolutionMatch</code> - نتیجه‌ی تطبیق اضطراری از <code>hosts</code> یا گزارش Optimize DNS است.</li>
  <li><code>CacheEntry</code> - کش‌های entry برای زمان انقضا و آدرس‌های resolved است.</li>
  <li><code>ResolveAttempt</code> - یک تلاش resolve روی یک DoH endpoint و خروجی آن را ثبت می‌کند.</li>
  <li><code>UpstreamProxyConfig</code> - تنظیمات و credentials مربوط به upstream proxy را نگه می‌دارد.</li>
  <li><code>UpstreamConnectResult</code> - نتیجه اتصال نهایی به مقصد، از جمله مسیر مستقیم یا proxied را نگه می‌دارد.</li>
</ul>

این مدل‌ها برای خواناتر شدن کد و کم کردن وابستگی به dict (دیکشنری)های خامِ مربوط به تنظیمات برنامه، نتیجه‌های resolve، ورودی‌های `hosts` و اطلاعات proxy استفاده می‌شوند.    

### 5) مدیریت Emergency Mode و hosts

این بخش به بازیابی سریع‌تر در شرایط اختلال کمک می‌کند:

<ul dir="rtl" align="right">
  <li><code>EmergencyDNSLookup</code></li>
  <li><code>HostsFileManager</code></li>
</ul>

در این لایه برنامه می‌تواند:

<ul dir="rtl" align="right">
  <li>فایل <code>hosts</code> را بخواند</li>
  <li>از فایل <code>hosts</code> بکاپ بگیرد</li>
  <li>ورودی‌های unmanaged قبلی را حفظ کند و رکوردهای مدیریت‌شده را merge/update کند</li>
  <li>در صورت نیاز <code>hosts</code> ویندوز را به‌روزرسانی کند</li>
</ul>

### 6) مدیریت proxy ویندوز و وضعیت اجرا

این قسمت به سیستم‌عامل وابسته است:

<ul dir="rtl" align="right">
  <li><code>WindowsSystemProxyManager</code> - وضعیت proxy ویندوز را snapshot، تنظیم و در صورت نیاز restore می‌کند.</li>
  <li><code>PortInUseError</code> - خطای اختصاصی برای زمانی که listen host/port قبلا اشغال شده باشد.</li>
  <li><code>is_admin()</code> - بررسی می‌کند برنامه با دسترسی Administrator اجرا شده یا نه.</li>
  <li><code>launch_elevated()</code> - برنامه را با سطح دسترسی بالاتر دوباره اجرا می‌کند.</li>
  <li><code>parse_listening_rows()</code> - خروجی netstat را به ردیف‌های قابل‌استفاده تبدیل می‌کند.</li>
  <li><code>listening_pids_for_target()</code> - تمامی PIDهای در حال گوش‌دادن روی listen host/port را پیدا می‌کند.</li>
</ul>

این بخش‌ها برای این استفاده می‌شوند که برنامه بتواند:

<ul dir="rtl" align="right">
  <li>تشخیص دهد روی پورت انتخابی چیزی در حال گوش‌دادن هست یا نه</li>
  <li>وضعیت پروکسی سیستم ویندوز را تنظیم یا برگرداند</li>
  <li>در صورت نیاز با سطح دسترسی Administrator اجرا شود</li>
</ul>

### 7) منوی تعاملی و config

این بخش منوی TUI ساده‌ی برنامه را می‌سازد و تنظیمات را بین اجراها نگه می‌دارد. (TUI مخفف `Text User Interface` است؛ یعنی
رابط کاربری متنی که با کیبورد و متن در ترمینال کار می‌کند):

<ul dir="rtl" align="right">
  <li><code>clear_screen()</code> - صفحه ترمینال را پاک می‌کند.</li>
  <li><code>_read_key()</code> - یک کلید فشرده‌شده را از ورودی می‌خواند.</li>
  <li><code>_read_prefilled_line()</code> - یک خط ورودی را با مقدار اولیه می‌خواند.</li>
  <li><code>prompt_edit_value()</code> - مقدار یک تنظیم را با اعتبارسنجی ویرایش می‌کند.</li>
  <li><code>prompt_optional_proxy_value()</code> - مقدار اختیاری proxy را از کاربر می‌گیرد.</li>
  <li><code>validate_listen_host()</code> - مقدار listen host را اعتبارسنجی می‌کند.</li>
  <li><code>validate_port()</code> - مقدار port را بررسی و به عدد تبدیل می‌کند.</li>
  <li><code>validate_non_empty_path()</code> - مسیر غیرخالی و معتبر را بررسی می‌کند.</li>
  <li><code>validate_optional_proxy()</code> - پروکسی اختیاری را validate می‌کند.</li>
  <li><code>_menu_rows()</code> - ردیف‌های قابل‌نمایش منو را می‌سازد.</li>
  <li><code>_fit_text()</code> - متن را با عرض مشخص fit می‌کند.</li>
  <li><code>_wrap_color()</code> - متن را با کد رنگی wrap می‌کند.</li>
  <li><code>print_verbose_error()</code> - خطای verbose را به شکل خوانا چاپ می‌کند.</li>
  <li><code>render_menu()</code> - منوی تنظیمات را رندر می‌کند.</li>
  <li><code>edit_selected_field()</code> - فیلد انتخاب‌شده را ویرایش می‌کند.</li>
  <li><code>toggle_selected_field()</code> - فیلدهای toggle را جابه‌جا می‌کند.</li>
  <li><code>load_namespace_from_config_file()</code> - تنظیمات را از فایل config بارگذاری می‌کند.</li>
  <li><code>should_show_menu()</code> - تصمیم می‌گیرد آیا منوی تعاملی نمایش داده شود یا نه.</li>
  <li><code>maybe_apply_system_proxy()</code> - در صورت نیاز proxy سیستم را اعمال می‌کند.</li>
  <li><code>start_proxy_session()</code> - session اصلی proxy را شروع می‌کند.</li>
  <li><code>run_interactive_menu()</code> - حلقه منوی تعاملی را اجرا می‌کند.</li>
</ul>

اگر در بخش UI یا تنظیمات تغییر می‌دهید، این ناحیه را با دقت بررسی کنید.

### 8) موتور DoH و اتصال شبکه

این بزرگ‌ترین بخش فنی فایل است و مسئول resolve و اتصال به مقصد است:

<ul dir="rtl" align="right">
  <li><code>DoHResolver</code> - درخواست‌های DoH را می‌سازد، resolve را انجام می‌دهد و fallbackها را مدیریت می‌کند.</li>
  <li><code>recv_until_header_end()</code> - داده را تا پایان header از سوکت می‌خواند.</li>
  <li><code>parse_headers()</code> - خطوط header را به جفت‌های key/value تبدیل می‌کند.</li>
  <li><code>get_header()</code> - مقدار یک header مشخص را از لیست headers برمی‌گرداند.</li>
  <li><code>split_host_port()</code> - مقادیر host و port را از یک رشته جدا می‌کند.</li>
  <li><code>origin_form_from_absolute_url()</code> - مقدار URL مطلق را به origin-form تبدیل می‌کند.</li>
  <li><code>format_host_port()</code> - مقادیر host و port را در قالب استاندارد می‌سازد.</li>
  <li><code>build_absolute_url()</code> - مقدار target را به URL مطلق روی host/port تبدیل می‌کند.</li>
  <li><code>parse_upstream_proxy()</code> - رشته proxy upstream را parse می‌کند.</li>
  <li><code>should_skip_forward_header()</code> - تصمیم می‌گیرد کدام headerها فوروارد نشوند.</li>
</ul>

این قسمت‌ها:

<ul dir="rtl" align="right">
  <li>درخواست DoH می‌سازند</li>
  <li>پاسخ را parse می‌کنند</li>
  <li>fallback بین endpointها را مدیریت می‌کنند</li>
  <li>proxy chaining را پشتیبانی می‌کنند</li>
  <li>address family و URL rewriting را کنترل می‌کنند</li>
</ul>

### 9) handler پروکسی

این بخش هسته‌ی request handling است:

<ul dir="rtl" align="right">
  <li><code>ProxyHandler</code> - هر اتصال client را پردازش می‌کند و درخواست‌ها را به مقصد هدایت می‌کند.</li>
  <li><code>ThreadedHTTPProxy</code> - سرور چندریسمانی proxy را برای سرویس‌دهی هم‌زمان به clientها اجرا می‌کند.</li>
  <li><code>make_server()</code> - سرور چندریسمانی proxy را می‌سازد و پیکربندی می‌کند.</li>
</ul>

رفتارهای اصلی این لایه:

<ul dir="rtl" align="right">
  <li>دریافت request از client</li>
  <li>resolve کردن host مقصد</li>
  <li>اتصال به IP نهایی</li>
  <li>tunnel کردن traffic</li>
  <li>مدیریت keep-alive و timeout</li>
  <li>ثبت traffic stats</li>
</ul>

اگر باگی در اتصال، fallback، timeout یا relay وجود دارد، معمولاً ریشه‌ی آن این بخش است.

### 10) خواندن فایل‌ها و شروع برنامه

در انتهای فایل، ورودی‌های اصلی برنامه قرار دارند:

<ul dir="rtl" align="right">
  <li><code>read_doh_file()</code> - فایل فهرست DoH را می‌خواند و خطوط معتبر را برمی‌گرداند.</li>
  <li><code>unique_preserve_order()</code> - موارد تکراری را با حفظ ترتیب حذف می‌کند.</li>
  <li><code>build_arg_parser()</code> - این parser آرگومان‌های خط فرمان را می‌سازد.</li>
  <li><code>main()</code> - جریان اصلی اجرای برنامه را مدیریت می‌کند.</li>
</ul>

این توابع مسئول:

<ul dir="rtl" align="right">
  <li>خواندن فهرست DoH endpointها</li>
  <li>حذف duplicateها با حفظ ترتیب</li>
  <li>ساخت CLI</li>
  <li>شروع چرخه‌ی اجرای برنامه</li>
</ul>

## پیشنهاد برای خواندن کد

اگر می‌خواهید سریع‌تر با `main.py` آشنا شوید، این ترتیب مناسب است:
<ol dir="rtl" align="right">
<li><code>main()</code> - نقطه شروع اجرای برنامه و مدیریت خطاهای سطح بالا.</li>
<li><code>build_arg_parser()</code> - همه آرگومان‌های خط فرمان و فلگ‌ها را تعریف می‌کند.</li>
<li><code>StartupConfig</code> - مدل اصلی تنظیمات runtime و مقدارهای پیش‌فرض را نگه می‌دارد.</li>
<li><code>start_proxy_session()</code> - نشست (session) اصلی proxy را از روی تنظیمات فعلی راه‌اندازی می‌کند.</li>
<li><code>DoHResolver</code> - ریزالور دامنه‌ها از طریق DoH و fallback بین endpointها را انجام می‌دهد.</li>
<li><code>ProxyHandler</code> - مسیر request/response هر client را اجرا می‌کند.</li>
<li><code>HostsFileManager</code> - تغییرات managed روی فایل `hosts` را ثبت و merge می‌کند.</li>
<li><code>WindowsSystemProxyManager</code> - پروکسی سیستم ویندوز را تنظیم و در پایان بازگردانی می‌کند.</li>
</ol>

این ترتیب از سطح اجرا به سمت هسته‌ی شبکه می‌رود و برای فهم وابستگی‌ها مناسب‌تر است.

## نقاط حساس برای تغییر

قبل از ویرایش این نواحی، اثر جانبی را بررسی کنید:

<ul dir="rtl" align="right">
  <li><code>DoHResolver</code> - هر تغییر در منطق resolve، cache، fallback یا proxy chaining را با دقت بررسی کنید.</li>
  <li><code>ProxyHandler</code> - حساس‌ترین نقطه برای request handling، tunneling و ثبت آمار است.</li>
  <li><code>HostsFileManager</code> - اشتباه در این بخش می‌تواند ورودی‌های <code>hosts</code> را overwrite کند یا backup را به‌هم بزند.</li>
  <li><code>WindowsSystemProxyManager</code> - مستقیم با تنظیمات proxy سیستم و registry سروکار دارد.</li>
  <li><code>start_proxy_session()</code> - ترتیب راه‌اندازی سرویس‌ها، error handling و shutdown اینجا کنترل می‌شود.</li>
  <li><code>run_interactive_menu()</code> - منطق UI، ذخیره تنظیمات و flow بازگشت به منو در این تابع جمع شده است.</li>
  <li><code>build_startup_config_from_namespace()</code> - ادغام config ذخیره‌شده با آرگومان‌های CLI را کنترل می‌کند.</li>
</ul>

تغییر در این بخش‌ها معمولاً فقط محلی نیست و روی رفتار runtime برنامه اثر مستقیم دارد.

</div>
