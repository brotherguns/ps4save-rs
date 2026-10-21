/* PS4 Save Tool for iOS — native UIKit front-end over the ps4save-rs core.
 * Built and linked by build.sh (no Xcode project needed).
 * Feature parity with the desktop egui GUI: Decrypt, Encrypt, Resign,
 * Reregion, Inspect + keystone / list / check-config / selftest utilities.
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <objc/runtime.h>

/* ---- FFI (ps4save-ios-core) -------------------------------------------- */
extern const char *ps4save_ios_version(void);
extern const char *ps4save_ios_documents_dir(void);
extern const char *ps4save_ios_default_config(void);
extern char *ps4save_ios_run(int cmd, const char *config, const char *input,
                             const char *output, const char *sample,
                             const char *account);
extern void ps4save_ios_free(char *p);

#define CMD_SELFTEST     0
#define CMD_DECRYPT      1
#define CMD_ENCRYPT      2
#define CMD_RESIGN       3
#define CMD_REREGION     4
#define CMD_INSPECT      5
#define CMD_KEYSTONE     6
#define CMD_LIST         7
#define CMD_CHECK_CONFIG 8

/* ---- palette (matches desktop gui settings.ini) -------------------------- */
static inline UIColor *PC(int r, int g, int b) {
    return [UIColor colorWithRed:r / 255.0 green:g / 255.0 blue:b / 255.0 alpha:1.0];
}
#define COL_BG     PC(18, 18, 20)
#define COL_BG2    PC(28, 28, 31)
#define COL_BG3    PC(40, 40, 44)
#define COL_BORDER PC(69, 61, 65)
#define COL_FG     PC(228, 228, 239)
#define COL_ACCENT PC(255, 204, 102)
#define COL_MUTED  PC(140, 140, 150)
#define COL_OK     PC(140, 200, 120)
#define COL_ERR    PC(220, 100, 100)

static UIFont *MonoFont(CGFloat size) {
    return [UIFont monospacedSystemFontOfSize:size weight:UIFontWeightRegular];
}

#pragma mark - ANSI -> NSAttributedString

/* Parse "\x1b[..m" SGR codes into an attributed string using the app palette.
 * Handles 0 (reset) and 31..36, the same set the desktop GUI maps. */
static NSAttributedString *AnsiAttributed(NSString *text) {
    UIFont *mono = MonoFont(12);
    NSDictionary *plain = @{ NSForegroundColorAttributeName : COL_FG,
                             NSFontAttributeName : mono };
    NSMutableAttributedString *out =
        [[NSMutableAttributedString alloc] initWithString:@"" attributes:plain];
    if (!text || !text.length) return out;

    NSDictionary<NSNumber *, UIColor *> *map =
        @{ @31 : PC(248, 113, 113), @32 : PC(74, 222, 128), @33 : PC(250, 222, 108),
           @34 : PC(90, 140, 250),  @35 : PC(220, 130, 250), @36 : PC(108, 220, 230) };

    NSUInteger len = [text length];
    const unichar ESC = 0x1b;
    NSMutableString *seg = [NSMutableString string];
    UIColor *cur = COL_FG;

    for (NSUInteger i = 0; i < len;) {
        unichar c = [text characterAtIndex:i];
        if (c != ESC) {
            [seg appendFormat:@"%C", c];
            i++;
            continue;
        }
        /* flush current segment */
        if (seg.length) {
            NSDictionary *a = @{ NSForegroundColorAttributeName : cur,
                                 NSFontAttributeName : mono };
            [out appendAttributedString:
                [[NSAttributedString alloc] initWithString:seg attributes:a]];
            [seg setString:@""];
        }
        i++;                                    /* skip ESC */
        if (i < len && [text characterAtIndex:i] == '[') {
            i++;                                /* skip '[' */
            NSString *params = @"";
            while (i < len) {
                unichar p = [text characterAtIndex:i];
                if (p == 'm') { i++; break; }
                if (p >= '0' && p <= '9') {
                    params = [params stringByAppendingFormat:@"%C", p];
                    i++;
                    continue;
                }
                i++;
                break;                          /* not an SGR we handle */
            }
            if (params.length) {
                int code = [params intValue];
                if (code == 0) cur = COL_FG;
                else {
                    UIColor *c2 = map[@(code)];
                    if (c2) cur = c2;
                }
            }
        }
    }
    if (seg.length) {
        NSDictionary *a = @{ NSForegroundColorAttributeName : cur,
                             NSFontAttributeName : mono };
        [out appendAttributedString:
            [[NSAttributedString alloc] initWithString:seg attributes:a]];
    }
    return out;
}

/* Strip ANSI escape codes and return the first line (for the status label). */
static NSString *PlainFirstLine(NSString *text) {
    NSString *line = text ?: @"";
    NSRange nl = [line rangeOfString:@"\n"];
    if (nl.location != NSNotFound) line = [line substringToIndex:nl.location];
    NSMutableString *outStr = [NSMutableString string];
    NSArray *parts = [line componentsSeparatedByString:@"\033"];
    for (NSUInteger i = 0; i < parts.count; i++) {
        NSString *p = parts[i];
        if (i == 0) { [outStr appendString:p]; continue; }
        NSRange mEnd = [p rangeOfString:@"m"];
        if ([p hasPrefix:@"[" ] && mEnd.location != NSNotFound)
            [outStr appendString:[p substringFromIndex:mEnd.location + 1]];
        else
            [outStr appendString:p];
    }
    return outStr;
}

#pragma mark - AppEngine

static NSString *EngKey(NSString *op, NSString *field) {
    return [op stringByAppendingFormat:@"/%@", field];
}

@interface AppEngine : NSObject
@property (nonatomic, strong) NSMutableDictionary *ops; /* op/field -> value */
@property (nonatomic, copy) NSString *configPath;
@property (nonatomic, assign) BOOL busy;
+ (instancetype)shared;
- (NSString *)get:(NSString *)op field:(NSString *)field;
- (void)set:(NSString *)op field:(NSString *)field value:(NSString *)v;
@end

@implementation AppEngine
+ (instancetype)shared {
    static AppEngine *e;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        e = [AppEngine new];
        e.ops = [NSMutableDictionary dictionary];
        const char *c = ps4save_ios_default_config();
        if (c) {
            e.configPath = [[NSString alloc] initWithUTF8String:c];
            ps4save_ios_free((char *)c);
        }
        e.busy = NO;
    });
    return e;
}
- (NSString *)get:(NSString *)op field:(NSString *)field {
    return [self.ops objectForKey:EngKey(op, field)] ?: @"";
}
- (void)set:(NSString *)op field:(NSString *)field value:(NSString *)v {
    NSString *key = EngKey(op, field);
    if (v.length) [self.ops setObject:v forKey:key];
    else [self.ops removeObjectForKey:key];
}
@end

#pragma mark - System file pickers

typedef void (^PickBlock)(NSString *path);

static NSString *MoveIntoImports(NSURL *src);

static NSString *DocumentsRoot(void) {
    return [NSString stringWithFormat:@"%@/Documents", NSHomeDirectory()];
}

/* Move a picker-returned copy into Documents/imports/<dir>/ so its path stays
 * valid across launches and lives under the core's workdir. For multi-picks
 * (a save PAIR: sealed .bin + image) the files land inside one folder which
 * the core then scans for pairs. */
static NSString *MoveIntoImportsBundle(NSArray<NSURL *> *urls) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = [DocumentsRoot() stringByAppendingPathComponent:@"imports"];
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES
                   attributes:nil error:nil];

    NSString *sub = urls.count > 1
        ? [NSString stringWithFormat:@"pair-%@",
              [[NSUUID UUID] UUIDString]]
        : urls.firstObject.lastPathComponent ?: @"picked.bin";

    if (urls.count > 1) {
        NSString *pairDir = [dir stringByAppendingPathComponent:sub];
        [fm createDirectoryAtPath:pairDir withIntermediateDirectories:YES
                       attributes:nil error:nil];
        for (NSURL *u in urls) {
            NSString *dst = [pairDir stringByAppendingPathComponent:
                                   u.lastPathComponent ?: @"file.bin"];
            NSInteger n = 1;
            while ([fm fileExistsAtPath:dst]) {
                NSString *stem = u.lastPathComponent.stringByDeletingPathExtension;
                NSString *ext = u.lastPathComponent.pathExtension;
                dst = [pairDir stringByAppendingPathComponent:
                    (ext.length
                        ? [NSString stringWithFormat:@"%@ (%ld).%@",
                              stem, (long)(n++), ext]
                        : [NSString stringWithFormat:@"%@ (%ld)",
                              stem, (long)(n++)])];
            }
            if (![fm moveItemAtURL:u toURL:[NSURL fileURLWithPath:dst] error:nil])
                [fm copyItemAtPath:u.path toPath:dst error:nil];
        }
        return pairDir;
    }
    return MoveIntoImports(urls.firstObject);
}

static NSString *MoveIntoImports(NSURL *src) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = [DocumentsRoot() stringByAppendingPathComponent:@"imports"];
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES
                   attributes:nil error:nil];
    NSString *name = src.lastPathComponent ?: @"picked.bin";
    NSString *dst = [dir stringByAppendingPathComponent:name];
    NSInteger n = 1;
    while ([fm fileExistsAtPath:dst]) {
        NSString *stem = [name stringByDeletingPathExtension];
        NSString *ext = name.pathExtension;
        dst = ext.length
            ? [dir stringByAppendingPathComponent:
                   [NSString stringWithFormat:@"%@ (%ld).%@",
                       stem, (long)(n++), ext]]
            : [dir stringByAppendingPathComponent:
                   [NSString stringWithFormat:@"%@ (%ld)", stem, (long)(n++)]];
    }
    if ([fm moveItemAtURL:src toURL:[NSURL fileURLWithPath:dst] error:nil])
        return dst;
    if ([fm copyItemAtPath:src.path toPath:dst error:nil]) return dst;
    return src.path; /* last resort: use the tmp copy directly */
}

static const void *kPickerHostKey = &kPickerHostKey;
static const void *kPickerDelegateKey = &kPickerDelegateKey;

/* Presents the system document picker and keeps the delegate alive via the
 * host association. importMode: the picked copy is moved into
 * Documents/imports (secure for later runs); exportMode: the picked (possibly
 * security-scoped) destination path is passed straight to the block. */
@interface PickerDelegate : NSObject <UIDocumentPickerDelegate>
@property (nonatomic, copy) PickBlock block;
@property (nonatomic, assign) BOOL importMode;
@property (nonatomic, assign) BOOL folderMode;
@property (nonatomic, assign) BOOL rawMode;
@property (nonatomic, copy) void (^rawBlock)(NSArray<NSURL *> *urls);
+ (void)showImport:(UIViewController *)host block:(PickBlock)cb;
+ (PickerDelegate *)showHost:(UIViewController *)host block:(PickBlock)cb;
+ (void)showFilesRaw:(UIViewController *)host
    block:(void (^)(NSArray<NSURL *> *urls))cb;
+ (void)activate:(UIDocumentPickerViewController *)p
        delegate:(PickerDelegate *)d host:(UIViewController *)host;
+ (void)showFolder:(UIViewController *)host block:(PickBlock)cb;
+ (void)showExport:(UIViewController *)host block:(PickBlock)cb
    suggested:(NSString *)name;
@end

@implementation PickerDelegate

+ (void)showImport:(UIViewController *)host block:(PickBlock)cb {
    PickerDelegate *d = [self showHost:host block:cb];
    if (!d) return;
    d.importMode = YES;
}

/* File-box flow: the callback receives the RAW picked URLs so it can route
 * each one into its own destination directory (the import wrapper stages
 * into an opaque pair-<uuid>/ dir, which boxes must not do). */
+ (void)showFilesRaw:(UIViewController *)host
    block:(void (^)(NSArray<NSURL *> *urls))cb {
    UIDocumentPickerViewController *p =
        [[UIDocumentPickerViewController alloc]
            initForOpeningContentTypes:@[
                [UTType typeWithIdentifier:@"public.item"]
            ]
                               asCopy:YES];
    p.allowsMultipleSelection = YES;
    PickerDelegate *d = [self showHost:host block:nil];
    d.rawMode = YES;
    d.rawBlock = [cb copy];
    [self activate:p delegate:d host:host];
}

+ (PickerDelegate *)showHost:(UIViewController *)host block:(PickBlock)cb {
    PickerDelegate *d = [PickerDelegate new];
    d.block = [cb copy];
    objc_setAssociatedObject(host, kPickerHostKey, d,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return d;
}

+ (void)showExport:(UIViewController *)host block:(PickBlock)cb
    suggested:(NSString *)name {
    PickerDelegate *d = [self showHost:host block:cb];
    if (!d) return;
    d.importMode = NO;

    NSString *stubDir =
        [NSTemporaryDirectory() stringByAppendingPathComponent:@"export"];
    [[NSFileManager defaultManager] createDirectoryAtPath:stubDir
        withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *stub = [stubDir stringByAppendingPathComponent:
        (name.length ? name : @"output.bin")];
    [[NSFileManager defaultManager] createFileAtPath:stub
        contents:[NSData data] attributes:nil];

    UIDocumentPickerViewController *p =
        [[UIDocumentPickerViewController alloc]
            initForExportingURLs:@[ [NSURL fileURLWithPath:stub] ] asCopy:YES];
    p.allowsMultipleSelection = NO;
    [self activate:p delegate:d host:host];
}

+ (void)activate:(UIDocumentPickerViewController *)p
        delegate:(PickerDelegate *)d host:(UIViewController *)host {
    p.delegate = d;
    [host presentViewController:p animated:YES completion:nil];
}

/* Apple's documented directory pattern: content type folder, asCopy NO,
 * then copy the picked tree ourselves while holding the security-scope
 * grant. The result is a normal folder under Documents/imports. */
static NSString *CopyDirectoryUnderScope(NSURL *dirURL) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *imports = [DocumentsRoot() stringByAppendingPathComponent:
                                               @"imports"];
    NSString *name = dirURL.lastPathComponent ?: @"save";
    NSString *dst = [imports stringByAppendingPathComponent:name];
    NSInteger n = 1;
    while ([fm fileExistsAtPath:dst]) {
        dst = [imports stringByAppendingPathComponent:
            [NSString stringWithFormat:@"%@ (%ld)", name, (long)(n++)]];
    }
    NSError *err = nil;
    [fm createDirectoryAtPath:[dst stringByDeletingLastPathComponent]
        withIntermediateDirectories:YES attributes:nil error:nil];
    BOOL scoped = [dirURL startAccessingSecurityScopedResource];
    BOOL ok = [fm copyItemAtPath:dirURL.path toPath:dst error:&err];
    if (scoped) [dirURL stopAccessingSecurityScopedResource];
    if (!ok) {
        NSString *msg = err.localizedDescription ?: @"copy failed";
        return [NSString stringWithFormat:@"__error__%@", msg];
    }
    return dst;
}

/* Exported constant from UTCoreTypes (a dynamic identifier lookup can
 * return nil and blow the picker array up — this cannot). */
extern UTType *const UTTypeFolder;

+ (void)showFolder:(UIViewController *)host block:(PickBlock)cb {
    PickerDelegate *d = [self showHost:host block:cb];
    if (!d) return;
    d.folderMode = YES;

    /* Legacy-pipeline switch: plist PS4LegacyPickerMode routes folder picks
     * through the pre-trust Import mode instead of the modern open-grant
     * machinery. The sideload signing ecosystem ships exactly this as its
     * "document picker fix" (VexSign's FilePickerForcePatch: import-mode
     * forcing + delegate relocation), evidence that Open-in-place stalls on
     * Feather-signed installs. */
    NSNumber *legacy = [NSBundle.mainBundle.infoDictionary
        objectForKey:@"PS4LegacyPickerMode"];
    UIDocumentPickerViewController *p;
    if (legacy.boolValue) {
        p = [[UIDocumentPickerViewController alloc]
            initWithDocumentTypes:@[ UTTypeFolder.identifier ]
                           inMode:UIDocumentPickerModeImport];
    } else {
        /* documented open-in-place form, no asCopy — for isolation testing
         * of non-app-container locations (iCloud Drive, Downloads,
         * providers) */
        p = [[UIDocumentPickerViewController alloc]
            initForOpeningContentTypes:@[ UTTypeFolder ]];
    }
    p.allowsMultipleSelection = NO;
    [self activate:p delegate:d host:host];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller
    didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (!urls.count) return;
    if (self.rawMode) {
        if (self.rawBlock) self.rawBlock(urls);
        return;
    }
    if (!self.block) return;
    if (self.folderMode) {
        self.block(CopyDirectoryUnderScope(urls.firstObject));
    } else if (self.importMode) {
        self.block(MoveIntoImportsBundle(urls));
    } else {
        self.block(urls.firstObject.path);
    }
}

- (void)documentPickerWasCancelled:
    (UIDocumentPickerViewController *)controller {}

@end

/* System import picker for files (input/sample/config rows). */
static void PresentImportPicker(UIViewController *host, PickBlock cb,
                                NSString *suggestedName) {
    UIDocumentPickerViewController *p =
        [[UIDocumentPickerViewController alloc]
            initForOpeningContentTypes:@[
                [UTType typeWithIdentifier:@"public.item"]
            ]
                               asCopy:YES];
    p.allowsMultipleSelection = YES;
    PickerDelegate *d = [PickerDelegate showHost:host block:cb];
    d.importMode = YES;
    [PickerDelegate activate:p delegate:d host:host];
}

#pragma mark - In-app sandbox folder browser

/* System folder pickers dead-end on the local provider for the app's own
 * container, so folder selection lives in-app: browse the Documents tree,
 * tap a folder to descend, "Use this folder" commits. */
@interface SaveBrowserVC : UITableViewController
@property (nonatomic, copy) NSString *currentDir;
@property (nonatomic, copy) NSString *rootDir;
@property (nonatomic, copy) void (^onPick)(NSString *path);
@property (nonatomic, strong) NSMutableArray<NSString *> *dirs;
@property (nonatomic, strong) NSMutableArray<NSString *> *files;
@end

@implementation SaveBrowserVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.rootDir = DocumentsRoot();
    if (!self.currentDir) self.currentDir = self.rootDir;
    self.title = @"Select folder";

    UIBarButtonItem *use =
        [[UIBarButtonItem alloc] initWithTitle:@"Use this folder"
            style:UIBarButtonItemStyleDone target:self
            action:@selector(useFolder)];
    UIBarButtonItem *close = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
        target:self action:@selector(dismissSelf)];
    use.accessibilityLabel = @"Use this folder";
    self.navigationItem.rightBarButtonItem = use;
    self.navigationItem.leftBarButtonItem = close;
    [self reload];
}

- (void)dismissSelf {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)useFolder {
    if (self.onPick) self.onPick(self.currentDir);
    [self dismissSelf];
}

- (void)reload {
    self.dirs = [NSMutableArray array];
    self.files = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *err = nil;
    NSArray *items = [fm contentsOfDirectoryAtPath:self.currentDir error:&err];
    for (NSString *name in [items sortedArrayUsingSelector:@selector(compare:)])
    {
        NSString *full =
            [self.currentDir stringByAppendingPathComponent:name];
        BOOL isDir = NO;
        if ([fm fileExistsAtPath:full isDirectory:&isDir]) {
            if (isDir) [self.dirs addObject:name];
            else [self.files addObject:name];
        }
    }
    [self.tableView reloadData];
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    return 1 + self.dirs.count + self.files.count; /* row 0 = ".." */
}

- (UITableViewCell *)tableView:(UITableView *)tv
        cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *cell = [tv dequeueReusableCellWithIdentifier:@"cell"];
    if (!cell)
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:@"cell"];
    cell.backgroundColor = COL_BG2;
    cell.textLabel.textColor = COL_FG;
    cell.textLabel.font = MonoFont(14);
    cell.detailTextLabel.textColor = COL_MUTED;
    cell.detailTextLabel.font = MonoFont(10);

    NSInteger i = ip.row;
    if (i == 0) {
        cell.textLabel.text = @"..";
        cell.detailTextLabel.text = self.currentDir;
        cell.accessoryType = UITableViewCellAccessoryNone;
    } else if (i <= (NSInteger)self.dirs.count) {
        NSString *name = self.dirs[i - 1];
        cell.textLabel.text = [name stringByAppendingString:@"/"];
        cell.detailTextLabel.text = @"";
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    } else {
        NSString *name = self.files[i - 1 - (NSInteger)self.dirs.count];
        NSString *full =
            [self.currentDir stringByAppendingPathComponent:name];
        NSDictionary *attr = [[NSFileManager defaultManager]
            attributesOfItemAtPath:full error:nil];
        cell.textLabel.text = name;
        cell.textLabel.textColor = COL_MUTED;
        cell.detailTextLabel.text =
            [NSString stringWithFormat:@"%llu B",
                (unsigned long long)[attr fileSize]];
        cell.accessoryType = UITableViewCellAccessoryNone;
    }
    return cell;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    NSInteger i = ip.row;
    if (i == 0) {
        if ([self.currentDir isEqualToString:self.rootDir]) return;
        self.currentDir = [self.currentDir stringByDeletingLastPathComponent];
        [self reload];
        return;
    }
    if (i <= (NSInteger)self.dirs.count) {
        self.currentDir = [self.currentDir
            stringByAppendingPathComponent:self.dirs[i - 1]];
        [self reload];
    }
    /* files are selectable by the picker elsewhere — here dirs only */
}

@end

#pragma mark - File boxes: rebuild a save folder from file picks

/* Copy one picked file into dir, dedup-suffixing on collision. Directories
 * cannot go into boxes; their names are reported back for the user note. */
static void CopyFileIntoDir(NSURL *src, NSString *dir,
                            NSMutableArray<NSString *> *skippedDirs) {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:src.path isDirectory:&isDir] || isDir) {
        [skippedDirs addObject:src.lastPathComponent ?: @"?"];
        return;
    }
    NSString *name = src.lastPathComponent ?: @"file.bin";
    NSString *dst = [dir stringByAppendingPathComponent:name];
    NSInteger n = 1;
    while ([fm fileExistsAtPath:dst]) {
        NSString *stem = [name stringByDeletingPathExtension];
        NSString *ext = name.pathExtension;
        dst = ext.length
            ? [dir stringByAppendingPathComponent:
                   [NSString stringWithFormat:@"%@ (%ld).%@",
                       stem, (long)(n++), ext]]
            : [dir stringByAppendingPathComponent:
                   [NSString stringWithFormat:@"%@ (%ld)", stem, (long)(n++)]];
    }
    [fm copyItemAtPath:src.path toPath:dst error:nil];
}

/* Two-slot flow over the working asCopy file picker: box 0 collects the
 * files of the save root, box 1 the files of sce_sys/. The rebuilt folder
 * is a normal tree the core treats exactly like a picked folder. */
@interface SaveBoxesVC : UITableViewController
@property (nonatomic, copy) void (^onCommit)(NSString *path);
@property (nonatomic, copy) NSString *buildDir;
@property (nonatomic, strong) NSMutableArray<NSString *> *saveFiles;
@property (nonatomic, strong) NSMutableArray<NSString *> *sysFiles;
@end

@implementation SaveBoxesVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"File boxes";
    if (!self.buildDir) {
        self.buildDir = [[DocumentsRoot() stringByAppendingPathComponent:
            [NSString stringWithFormat:@"imports/rebuild-%@",
                [[NSUUID UUID] UUIDString]]] copy];
    }
    self.saveFiles = [NSMutableArray new];
    self.sysFiles = [NSMutableArray new];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithTitle:@"Build & use" style:UIBarButtonItemStyleDone
        target:self action:@selector(buildTapped)];
    UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc]
        initWithTarget:self action:@selector(longPress:)];
    [self.tableView addGestureRecognizer:lp];
}

- (NSString *)boxDir:(NSInteger)boxIdx {
    return boxIdx == 0
        ? self.buildDir
        : [self.buildDir stringByAppendingPathComponent:@"sce_sys"];
}

- (NSMutableArray<NSString *> *)boxFiles:(NSInteger)boxIdx {
    return boxIdx == 0 ? self.saveFiles : self.sysFiles;
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tv {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tv
    numberOfRowsInSection:(NSInteger)s {
    return 2;
}

- (UITableViewCell *)tableView:(UITableView *)tv
    cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *c = [self.tableView dequeueReusableCellWithIdentifier:@"b"];
    if (!c) c = [[UITableViewCell alloc]
        initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:@"b"];
    c.textLabel.text = (ip.row == 0) ? @"save files" : @"sce_sys files";
    NSInteger n = [self boxFiles:ip.row].count;
    c.detailTextLabel.text = n
        ? [NSString stringWithFormat:@"%ld file%s picked",
              (long)n, n == 1 ? "" : "s"]
        : @"tap to pick";
    c.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    return c;
}

- (NSString *)tableView:(UITableView *)tv
    titleForFooterInSection:(NSInteger)s {
    return @"Pick FILES, not folders. The sce_sys box must include "
           @"param.sfo \u2014 Build is refused without it.";
}

- (void)tableView:(UITableView *)tv
    didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    [self pickForBox:ip.row];
}

- (void)longPress:(UILongPressGestureRecognizer *)gr {
    if (gr.state != UIGestureRecognizerStateBegan) return;
    CGPoint p = [gr locationInView:self.tableView];
    NSIndexPath *ip = [self.tableView indexPathForRowAtPoint:p];
    if (!ip) return;
    NSMutableArray<NSString *> *box = [self boxFiles:ip.row];
    if (!box.count) return;
    UIAlertController *a = [UIAlertController
        alertControllerWithTitle:(ip.row == 0) ? @"save files" : @"sce_sys files"
        message:@"Clear every file in this box?"
        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"Clear"
        style:UIAlertActionStyleDestructive handler:^(UIAlertAction *act) {
            NSFileManager *fm = [NSFileManager defaultManager];
            for (NSString *fn in box)
                [fm removeItemAtPath:
                    [[self boxDir:ip.row]
                        stringByAppendingPathComponent:fn]
                    error:nil];
            [box removeAllObjects];
            [self.tableView reloadRowsAtIndexPaths:@[ip]
                withRowAnimation:UITableViewRowAnimationNone];
        }]];
    [a addAction:[UIAlertAction actionWithTitle:@"Keep"
        style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)noteSkipped:(NSArray<NSString *> *)skipped {
    UIAlertController *a = [UIAlertController
        alertControllerWithTitle:@"Folders can't go in boxes"
        message:[skipped componentsJoinedByString:@", "]
        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"Pick the files inside"
        style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)reloadBoxRow:(NSInteger)boxIdx {
    [self.tableView reloadRowsAtIndexPaths:
        @[[NSIndexPath indexPathForRow:boxIdx inSection:0]]
        withRowAnimation:UITableViewRowAnimationNone];
}

- (void)pickForBox:(NSInteger)boxIdx {
    NSString *dst = [self boxDir:boxIdx];
    [[NSFileManager defaultManager] createDirectoryAtPath:dst
        withIntermediateDirectories:YES attributes:nil error:nil];
    __weak SaveBoxesVC *ws = self;
    [PickerDelegate showFilesRaw:self block:^(NSArray<NSURL *> *urls) {
        __strong SaveBoxesVC *s = ws;
        if (!s) return;
        NSMutableArray<NSString *> *skipped = [NSMutableArray new];
        for (NSURL *u in urls) CopyFileIntoDir(u, dst, skipped);
        NSMutableArray<NSString *> *box = [s boxFiles:boxIdx];
        [box removeAllObjects];
        [box addObjectsFromArray:
            [[NSFileManager defaultManager]
                contentsOfDirectoryAtPath:dst error:nil]];
        [s reloadBoxRow:boxIdx];
        if (skipped.count) [s noteSkipped:skipped];
    }];
}

- (void)buildTapped {
    if (![NSFileManager.defaultManager fileExistsAtPath:
            [[self boxDir:1] stringByAppendingPathComponent:@"param.sfo"]]) {
        UIAlertController *a = [UIAlertController
            alertControllerWithTitle:@"sce_sys box is missing param.sfo"
            message:@"The encryptor reads SAVEDATA_BLOCKS and the save's "
                    @"directory name from it. Pick param.sfo into the "
                    @"sce_sys box first."
            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"Ok"
            style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:a animated:YES completion:nil];
        return;
    }
    NSString *path = self.buildDir;
    [self.navigationController dismissViewControllerAnimated:YES
        completion:nil];
    if (self.onCommit) self.onCommit(path);
}

@end

#pragma mark - Command view controller

/* Shared command screen. WHAT rows appear is driven by wants* flags; layout
 * is recomputed in viewDidLayoutSubviews so it follows rotation + safe areas.
 * Input-type rows open the system import picker (any file, anywhere); the
 * output row opens the system export picker and the core writes directly
 * into the picked security-scoped location. */
@interface CommandVC : UIViewController <UITextFieldDelegate>
@property (nonatomic, assign) int cmd;      /* ffi command id */
@property (nonatomic, copy) NSString *op;   /* engine key (decrypt/...) */
@property (nonatomic, copy) NSString *runTitle;
@property (nonatomic, assign) BOOL wantsConfig;
@property (nonatomic, assign) BOOL wantsOutput;
@property (nonatomic, assign) BOOL wantsSample;
@property (nonatomic, assign) BOOL wantsAccount;
@property (nonatomic, assign) BOOL needsInput; /* gate on input (default YES) */
@property (nonatomic, assign) BOOL wantsImportConfig; /* utils: ensure config */
@property (nonatomic, assign) BOOL inputWantsFolder; /* encrypt: pick a dir */

@property (nonatomic, strong) UITextField *configField;
@property (nonatomic, strong) UITextField *inputField;
@property (nonatomic, strong) UITextField *sampleField;
@property (nonatomic, strong) UITextField *outputField;
@property (nonatomic, strong) UITextField *accountField;
@property (nonatomic, strong) UIButton *runBtn;
@property (nonatomic, strong) UIView *statusPill;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UITextView *outputView;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;

- (void)dismissKeyboard;
- (void)runTapped;
- (void)shareOutput;
@end

static const void *kFieldRefKey = &kFieldRefKey;
static const void *kKindRefKey = &kKindRefKey;

@implementation CommandVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = COL_BG;
    self.needsInput = YES;

    if (self.wantsConfig) [self buildRowFor:@"config"];
    [self buildRowFor:@"input"];
    if (self.wantsSample) [self buildRowFor:@"sample"];
    if (self.wantsOutput) [self buildRowFor:@"output"];
    if (self.wantsAccount) [self buildRowFor:@"account"];

    /* big run button */
    UIButtonConfiguration *rc =
        [UIButtonConfiguration filledButtonConfiguration];
    rc.title = (self.runTitle ?: self.op).uppercaseString;
    rc.image = [UIImage systemImageNamed:@"play.fill"];
    rc.imagePadding = 6;
    rc.background.cornerRadius = 12;
    rc.baseBackgroundColor = COL_ACCENT;
    rc.baseForegroundColor = PC(24, 22, 16);
    self.runBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.runBtn.configuration = rc;
    self.runBtn.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    [self.runBtn addTarget:self action:@selector(runTapped)
        forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.runBtn];

    /* status pill */
    self.statusPill = [UIView new];
    self.statusPill.layer.cornerRadius = 10;
    self.statusPill.layer.masksToBounds = YES;
    [self.view addSubview:self.statusPill];

    self.statusLabel = [UILabel new];
    self.statusLabel.font = MonoFont(12);
    self.statusLabel.numberOfLines = 2;
    [self.statusPill addSubview:self.statusLabel];

    /* output console */
    self.outputView = [UITextView new];
    self.outputView.backgroundColor = COL_BG2;
    self.outputView.layer.cornerRadius = 10;
    self.outputView.layer.borderColor = COL_BORDER.CGColor;
    self.outputView.layer.borderWidth = 1;
    self.outputView.editable = NO;
    self.outputView.showsVerticalScrollIndicator = YES;
    self.outputView.textContainerInset = UIEdgeInsetsMake(10, 10, 10, 10);
    self.outputView.userInteractionEnabled = YES;
    [self.view addSubview:self.outputView];

    self.spinner = [[UIActivityIndicatorView alloc]
        initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spinner.color = COL_FG;
    [self.view addSubview:self.spinner];

    UIBarButtonItem *share = [[UIBarButtonItem alloc]
        initWithImage:[UIImage systemImageNamed:@"square.and.arrow.up"]
        style:UIBarButtonItemStylePlain
        target:self action:@selector(shareOutput)];
    share.enabled = NO;
    self.navigationItem.rightBarButtonItem = share;

    [self hydrate];

    if (self.wantsImportConfig) {
        UIBarButtonItem *imp = [[UIBarButtonItem alloc]
            initWithImage:[UIImage systemImageNamed:@"square.and.arrow.up.fill"]
            style:UIBarButtonItemStylePlain target:self
            action:@selector(importConfigTapped)];
        self.navigationItem.leftBarButtonItem = imp;
    }
}

/* Utils tab: pull an external config.ini into Documents on first launch.
 * Rules: if a config already exists we refuse (never merge keys into an
 * existing file, never overwrite the user's keys); the picked file is
 * copied UNCHANGED and becomes the active config. */
- (void)importConfigTapped {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dst = [[DocumentsRoot() stringByAppendingPathComponent:
                      @"config.ini"] stringByAppendingString:@""];
    if ([fm fileExistsAtPath:dst]) {
        UIAlertController *a = [UIAlertController
            alertControllerWithTitle:@"Config exists"
            message:@"Documents/config.ini is already set. Existing configs "
                    @"are never modified — remove it in the Files app first "
                    @"if you want to replace it."
            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"OK"
            style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:a animated:YES completion:nil];
        return;
    }

    __weak CommandVC *ws = self;
    void (^picked)(NSString *) = ^(NSString *path) {
        __strong CommandVC *s = ws;
        if (!s) return;
        NSFileManager *fm2 = [NSFileManager defaultManager];
        if ([fm2 fileExistsAtPath:dst]) {
            [fm2 removeItemAtPath:path error:nil];
            return;
        }
        if (![fm2 copyItemAtPath:path toPath:dst error:nil]) {
            [s setStatus:@"copy failed" kind:@"err"];
            return;
        }
        [fm2 removeItemAtPath:path error:nil]; /* drop the import copy */
        [AppEngine shared].configPath = dst;
        if (s.configField) s.configField.text = dst;
        [s persist];
        UINotificationFeedbackGenerator *g =
            [UINotificationFeedbackGenerator new];
        [g notificationOccurred:UINotificationFeedbackTypeSuccess];
        [s setStatus:@"config imported; you're set" kind:@"ok"];
    };
    PresentImportPicker(self, picked, @"config.ini");
}

/* One field card: caption + rounded container(field + browse icon button).
 * Views are created without frames; placement happens in viewDidLayoutSubviews. */
- (void)buildRowFor:(NSString *)kind {
    NSString *title, *hint, *icon;
    BOOL isOutput = NO;
    BOOL isFolderPick =
        [kind isEqualToString:@"input"] && self.inputWantsFolder;
    if ([kind isEqualToString:@"config"]) {
        title = @"CONFIG"; hint = @"config.ini path";
        icon = @"gearshape";
    } else if ([kind isEqualToString:@"input"]) {
        title = isFolderPick ? @"SAVE FOLDER" : @"INPUT FILE";
        hint = isFolderPick ? @"pick the save folder (contains sce_sys)..."
                            : @"pick a save from anywhere...";
        icon = isFolderPick ? @"folder" : @"doc.badge.plus";
    } else if ([kind isEqualToString:@"sample"]) {
        title = @"REGION SAMPLE"; hint = @"target region save...";
        icon = @"folder";
    } else if ([kind isEqualToString:@"output"]) {
        title = @"OUTPUT";
        hint = @"empty = Documents/<command>/";
        icon = @"square.and.arrow.down";
        isOutput = YES;
    } else {
        title = @"ACCOUNT ID"; hint = @"0000000000000000";
        icon = @"person";
    }

    NSInteger idx = [self kindIndexForKind:kind];

    UILabel *l = [UILabel new];
    l.text = title;
    l.textColor = COL_ACCENT;
    l.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    l.tag = idx + 100;
    [self.view addSubview:l];

    UIView *card = [UIView new];
    card.backgroundColor = COL_BG2;
    card.layer.cornerRadius = 10;
    card.layer.borderColor = COL_BORDER.CGColor;
    card.layer.borderWidth = 1;
    card.layer.masksToBounds = YES;
    card.tag = idx + 200;
    [self.view addSubview:card];

    UITextField *tf = [UITextField new];
    tf.placeholder = hint;
    tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    tf.keyboardType = UIKeyboardTypeASCIICapable;
    tf.autocorrectionType = UITextAutocorrectionTypeNo;
    tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tf.returnKeyType = UIReturnKeyDone;
    tf.textColor = COL_FG;
    tf.font = MonoFont(12);
    tf.delegate = self;

    /* keyboard done bar */
    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, 0,
        [UIScreen mainScreen].bounds.size.width, 44)];
    bar.backgroundColor = COL_BG3;
    UIButton *doneBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    doneBtn.frame = CGRectMake(
        [UIScreen mainScreen].bounds.size.width - 80, 4, 70, 36);
    [doneBtn setTitle:@"Done" forState:UIControlStateNormal];
    [doneBtn setTitleColor:COL_ACCENT forState:UIControlStateNormal];
    [doneBtn addTarget:self action:@selector(dismissKeyboard)
        forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:doneBtn];
    tf.inputAccessoryView = bar;

    /* browse icon button (kind association drives import vs export) */
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.tintColor = COL_ACCENT;
    [b setImage:[UIImage systemImageNamed:icon]
        forState:UIControlStateNormal];
    b.accessibilityLabel = @"Browse";
    [b addTarget:self action:@selector(browseTapped:)
        forControlEvents:UIControlEventTouchUpInside];

    objc_setAssociatedObject(b, &kFieldRefKey, tf,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(b, &kKindRefKey, kind,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    [card addSubview:tf];
    [card addSubview:b];

    if ([kind isEqualToString:@"config"]) self.configField = tf;
    else if ([kind isEqualToString:@"input"]) self.inputField = tf;
    else if ([kind isEqualToString:@"sample"]) self.sampleField = tf;
    else if ([kind isEqualToString:@"output"]) self.outputField = tf;
    else self.accountField = tf;
}

- (void)dismissKeyboard {
    [self.view endEditing:YES];
}

- (BOOL)textFieldShouldReturn:(UITextField *)tf {
    [tf resignFirstResponder];
    [self persist];
    return YES;
}

- (void)textFieldDidEndEditing:(UITextField *)tf {
    [self persist];
}

- (void)persist {
    AppEngine *e = [AppEngine shared];
    if (self.configField) e.configPath = self.configField.text;
    if (self.inputField)
        [e set:self.op field:@"input" value:self.inputField.text];
    if (self.sampleField)
        [e set:self.op field:@"sample" value:self.sampleField.text];
    if (self.outputField)
        [e set:self.op field:@"output" value:self.outputField.text];
    if (self.accountField)
        [e set:self.op field:@"account" value:self.accountField.text];
}

- (void)hydrate {
    AppEngine *e = [AppEngine shared];
    if (self.configField) self.configField.text = e.configPath;
    if (self.inputField)
        self.inputField.text = [e get:self.op field:@"input"];
    if (self.sampleField)
        self.sampleField.text = [e get:self.op field:@"sample"];
    if (self.outputField)
        self.outputField.text = [e get:self.op field:@"output"];
    if (self.accountField) {
        self.accountField.text = [e get:self.op field:@"account"];
        if (!self.accountField.text.length)
            self.accountField.text = @"0000000000000000";
    }
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGFloat top = self.view.safeAreaInsets.top + 6;
    CGFloat bottom = self.view.safeAreaInsets.bottom;
    CGFloat w = self.view.bounds.size.width;
    CGFloat y = top;

    /* place rows in declared order */
    if (self.wantsConfig && self.configField)
        y = [self placeRowKind:@"config" y:y w:w];
    if (self.inputField)
        y = [self placeRowKind:@"input" y:y w:w];
    if (self.wantsSample && self.sampleField)
        y = [self placeRowKind:@"sample" y:y w:w];
    if (self.wantsOutput && self.outputField)
        y = [self placeRowKind:@"output" y:y w:w];
    if (self.wantsAccount && self.accountField)
        y = [self placeRowKind:@"account" y:y w:w];

    self.runBtn.frame = CGRectMake(16, y + 6, w - 32.0, 52);
    CGFloat py = y + 58 + 8;
    CGFloat pillH = 30;
    self.statusPill.frame = CGRectMake(16, py, w - 32.0, pillH);
    self.statusLabel.frame = CGRectMake(12, 7, (w - 32.0) - 24, 16);
    CGFloat oy = py + pillH + 10;
    self.outputView.frame = CGRectMake(16, oy, w - 32.0,
        self.view.bounds.size.height - bottom - oy - 12);
    self.spinner.frame = CGRectMake(w - 48, y + 6 + 16, 20, 20);
}

/* caption above, card below (field + browse inside); returns next row's y */
- (CGFloat)placeRowKind:(NSString *)kind y:(CGFloat)y w:(CGFloat)w {
    NSInteger idx = [self kindIndexForKind:kind];
    UILabel *l = [self labelWithTag:idx + 100];
    if (l) l.frame = CGRectMake(18, y, w - 36, 14);
    CGFloat cy = y + 18;
    CGFloat cardH = 46;

    UIView *card = [self cardWithTag:idx + 200];
    if (card) {
        card.frame = CGRectMake(16, cy, w - 32.0, cardH);
        UITextField *tf = [self fieldForCard:card];
        if (tf) tf.frame = CGRectMake(12, 0, (w - 32.0) - 12 - 46 - 12, cardH);
        UIButton *b = [self browseForCard:card];
        if (b) b.frame = CGRectMake((w - 32.0) - 46, 3, 44, cardH - 6);
    }
    return cy + cardH + 14;
}

- (NSInteger)kindIndexForKind:(NSString *)kind {
    if ([kind isEqualToString:@"config"]) return 0;
    if ([kind isEqualToString:@"input"]) return 1;
    if ([kind isEqualToString:@"sample"]) return 2;
    if ([kind isEqualToString:@"output"]) return 3;
    return 4;
}

- (UILabel *)labelWithTag:(NSInteger)tag {
    for (UIView *v in self.view.subviews)
        if ([v isKindOfClass:[UILabel class]] && v.tag == tag)
            return (UILabel *)v;
    return nil;
}

- (UIView *)cardWithTag:(NSInteger)tag {
    for (UIView *v in self.view.subviews)
        if ([v isKindOfClass:[UIView class]] && v.tag == tag)
            return v;
    return nil;
}

/* fields and browse buttons live INSIDE their card */
- (UITextField *)fieldForCard:(UIView *)card {
    for (UIView *v in card.subviews)
        if ([v isKindOfClass:[UITextField class]]) return (UITextField *)v;
    return nil;
}

- (UIButton *)browseForCard:(UIView *)card {
    for (UIView *v in card.subviews)
        if ([v isKindOfClass:[UIButton class]]) return (UIButton *)v;
    return nil;
}

- (void)browseTapped:(UIButton *)b {
    UITextField *tf = objc_getAssociatedObject(b, &kFieldRefKey);
    NSString *kind = objc_getAssociatedObject(b, &kKindRefKey);
    if (!tf || !kind) return;
    __weak CommandVC *ws = self;

    void (^onPick)(NSString *) = ^(NSString *path) {
        __strong CommandVC *s = ws;
        if (!s) return;
        if ([path hasPrefix:@"__error__"]) {
            [s setStatus:[path substringFromIndex:9] kind:@"err"];
            return;
        }
        tf.text = path;
        [s persist];
    };

    if ([kind isEqualToString:@"output"]) {
        /* suggested name follows what was last used for this row */
        NSString *sug = tf.text.lastPathComponent;
        if (!sug.length)
            sug = [NSString stringWithFormat:@"%@-output.bin", self.op];
        [PickerDelegate showExport:self block:onPick suggested:sug];
    } else if ([kind isEqualToString:@"input"] && self.inputWantsFolder) {
        UIAlertController *how = [UIAlertController
            alertControllerWithTitle:@"Pick folder"
            message:@"Where does the save folder live?"
            preferredStyle:UIAlertControllerStyleAlert];
        void (^commit)(NSString *) = ^(NSString *path) {
            __strong CommandVC *s = ws;
            if (!s) return;
            if ([path hasPrefix:@"__error__"]) {
                [s setStatus:[path substringFromIndex:9] kind:@"err"];
                return;
            }
            tf.text = path;
            [s persist];
        };
        void (^presentBrowser)(void) = ^{
            __strong CommandVC *s = ws;
            if (!s) return;
            SaveBrowserVC *b = [SaveBrowserVC new];
            b.onPick = commit;
            UINavigationController *nav = [[UINavigationController alloc]
                initWithRootViewController:b];
            nav.navigationBar.barStyle = UIBarStyleBlack;
            [s presentViewController:nav animated:YES completion:nil];
        };
        void (^presentSystem)(void) = ^{
            __strong CommandVC *s = ws;
            if (!s) return;
            [PickerDelegate showFolder:s block:commit];
        };
        void (^presentBoxes)(void) = ^{
            __strong CommandVC *s = ws;
            if (!s) return;
            SaveBoxesVC *b = [SaveBoxesVC new];
            b.onCommit = commit;
            UINavigationController *nav = [[UINavigationController alloc]
                initWithRootViewController:b];
            nav.navigationBar.barStyle = UIBarStyleBlack;
            [s presentViewController:nav animated:YES completion:nil];
        };
        [how addAction:[UIAlertAction actionWithTitle:
            @"File boxes: pick files, rebuild folder (works everywhere)"
            style:UIAlertActionStyleDefault handler:^(UIAlertAction *act) {
                presentBoxes();
            }]];

        [how addAction:[UIAlertAction actionWithTitle:
            @"In-app: browse Documents (recommended)"
            style:UIAlertActionStyleDefault handler:^(UIAlertAction *act) {
                presentBrowser();
            }]];
        [how addAction:[UIAlertAction actionWithTitle:
            @"System folder picker (iCloud / Downloads)"
            style:UIAlertActionStyleDefault handler:^(UIAlertAction *act) {
                presentSystem();
            }]];
        [how addAction:[UIAlertAction actionWithTitle:@"Cancel"
            style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:how animated:YES completion:nil];
    } else {
        PresentImportPicker(self, onPick, tf.text.lastPathComponent);
    }
}

- (void)runTapped {
    [self persist];
    AppEngine *e = [AppEngine shared];
    if (e.busy) return;

    if (self.needsInput && !self.inputField.text.length) {
        [self setStatus:@"pick an input file first" kind:@"err"];
        return;
    }

    e.busy = YES;
    self.runBtn.enabled = NO;
    self.runBtn.alpha = 0.55;
    [self.spinner startAnimating];
    [self setStatus:@"working..." kind:@"load"];

    NSString *config = e.configPath ?: @"";
    NSString *input = self.inputField.text ?: @"";
    NSString *output = self.outputField.text ?: @"";
    NSString *sample = self.sampleField.text ?: @"";
    NSString *account = self.accountField.text ?: @"";
    int cmd = self.cmd;
    __weak CommandVC *weakself = self;

    /* An output path picked from the export picker is only writable while we
     * hold its security-scope grant in this process. */
    NSURL *outURL = output.length ? [NSURL fileURLWithPath:output] : nil;
    BOOL scoped = outURL && ![output hasPrefix:DocumentsRoot()] &&
                  [outURL startAccessingSecurityScopedResource];

    dispatch_async(
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            char *raw = ps4save_ios_run(cmd, config.UTF8String,
                                        input.UTF8String, output.UTF8String,
                                        sample.UTF8String, account.UTF8String);
            NSString *text =
                raw ? [[NSString alloc] initWithUTF8String:raw] : @"";
            if (raw) ps4save_ios_free(raw);
            dispatch_async(dispatch_get_main_queue(), ^{
                __strong CommandVC *s = weakself;
                [AppEngine shared].busy = NO;
                if (scoped) [outURL stopAccessingSecurityScopedResource];
                if (!s) return;            /* vc gone: engine already freed */
                s.runBtn.enabled = YES;
                s.runBtn.alpha = 1.0;
                [s.spinner stopAnimating];
                BOOL isErr =
                    [text rangeOfString:@"error"].location != NSNotFound;
                s.outputView.attributedText = AnsiAttributed(text);
                [s setStatus:PlainFirstLine(text)
                        kind:isErr ? @"err" : @"ok"];
                if (!isErr) {
                    UINotificationFeedbackGenerator *g =
                        [UINotificationFeedbackGenerator new];
                    [g notificationOccurred:
                        UINotificationFeedbackTypeSuccess];
                    s.navigationItem.rightBarButtonItem.enabled =
                        s.outputView.text.length > 0;
                }
            });
        });
}

- (void)setStatus:(NSString *)msg kind:(NSString *)kind {
    UIColor *c;
    if ([kind isEqualToString:@"ok"]) c = COL_OK;
    else if ([kind isEqualToString:@"err"]) c = COL_ERR;
    else c = COL_ACCENT;
    self.statusLabel.textColor = c;
    self.statusLabel.text = msg;
    self.statusPill.backgroundColor = [c colorWithAlphaComponent:0.12];
}

- (void)shareOutput {
    /* share the produced file when we know where it is, else the text */
    NSString *outPath = self.outputField.text ?: @"";
    NSArray *items;
    if (outPath.length && [[NSFileManager defaultManager]
            fileExistsAtPath:outPath]) {
        items = @[ [NSURL fileURLWithPath:outPath] ];
    } else {
        NSString *plain = self.outputView.text ?: @"";
        NSString *tmpTxt = [NSTemporaryDirectory()
            stringByAppendingPathComponent:
                [NSString stringWithFormat:@"%@-output.txt", self.op]];
        NSData *d = [plain dataUsingEncoding:NSUTF8StringEncoding];
        [d writeToFile:tmpTxt atomically:YES];
        items = @[ [NSURL fileURLWithPath:tmpTxt] ];
    }
    UIActivityViewController *av =
        [[UIActivityViewController alloc] initWithActivityItems:items
            applicationActivities:nil];
    [self presentViewController:av animated:YES completion:nil];
}

@end

#pragma mark - App delegate

#pragma mark - Scene lifecycle

/* Adopted scene-based lifecycle: non-scene apps are the legacy path Apple is
 * sunsetting (iOS 27 SDK builds must adopt scenes), and open-in-place grants
 * handed to a document picker are routed through the scene pipeline on
 * modern iOS. Folder picking currently dead-ends on non-scene builds. */

static void StyleSystemBars(void) {
    UINavigationBarAppearance *ap = [UINavigationBarAppearance new];
    [ap configureWithOpaqueBackground];
    ap.backgroundColor = COL_BG;
    ap.shadowColor = nil;
    ap.titleTextAttributes =
        @{ NSForegroundColorAttributeName : COL_FG };
    [[UINavigationBar appearance] setStandardAppearance:ap];
    [[UINavigationBar appearance] setScrollEdgeAppearance:ap];

    UITabBarAppearance *ta = [UITabBarAppearance new];
    [ta configureWithOpaqueBackground];
    ta.backgroundColor = COL_BG;
    ta.shadowColor = nil;
    [[UITabBar appearance] setStandardAppearance:ta];
}

/* The six command tabs; built here so the scene-connect path (the only
 * launch path now) owns one definition. */
static UITabBarController *MakeRootController(void) {
    /* decrypt */
    CommandVC *decrypt = [CommandVC new];
    decrypt.cmd = CMD_DECRYPT;
    decrypt.op = @"decrypt";
    decrypt.runTitle = @"Decrypt";
    decrypt.wantsOutput = YES;
    decrypt.title = @"Decrypt";
    decrypt.tabBarItem.image = [UIImage systemImageNamed:@"lock.open"];

    /* encrypt: encrypt takes an extracted save FOLDER (sce_sys inside) */
    CommandVC *encrypt = [CommandVC new];
    encrypt.cmd = CMD_ENCRYPT;
    encrypt.op = @"encrypt";
    encrypt.runTitle = @"Encrypt";
    encrypt.wantsOutput = YES;
    encrypt.inputWantsFolder = YES;
    encrypt.title = @"Encrypt";
    encrypt.tabBarItem.image = [UIImage systemImageNamed:@"lock"];

    /* resign */
    CommandVC *resign = [CommandVC new];
    resign.cmd = CMD_RESIGN;
    resign.op = @"resign";
    resign.runTitle = @"Resign";
    resign.wantsOutput = YES;
    resign.wantsAccount = YES;
    resign.title = @"Resign";
    resign.tabBarItem.image = [UIImage systemImageNamed:@"signature"];

    /* reregion */
    CommandVC *reregion = [CommandVC new];
    reregion.cmd = CMD_REREGION;
    reregion.op = @"reregion";
    reregion.runTitle = @"Reregion";
    reregion.wantsOutput = YES;
    reregion.wantsSample = YES;
    reregion.wantsAccount = YES;
    reregion.title = @"Reregion";
    reregion.tabBarItem.image = [UIImage systemImageNamed:@"globe"];

    /* inspect */
    CommandVC *inspect = [CommandVC new];
    inspect.cmd = CMD_INSPECT;
    inspect.op = @"inspect";
    inspect.runTitle = @"Inspect";
    inspect.needsInput = YES;
    inspect.title = @"Inspect";
    inspect.tabBarItem.image = [UIImage systemImageNamed:@"magnifyingglass"];

    /* utils: config path + check-config (uses output row for info display) */
    CommandVC *settings = [CommandVC new];
    settings.cmd = CMD_CHECK_CONFIG;
    settings.op = @"utils";
    settings.runTitle = @"Check Config";
    settings.wantsConfig = YES;
    settings.wantsOutput = YES;
    settings.needsInput = NO;
    settings.wantsImportConfig = YES;
    settings.title = @"Utils";
    settings.tabBarItem.image = [UIImage systemImageNamed:@"gearshape"];

    StyleSystemBars();

    UINavigationController *nd =
        [[UINavigationController alloc] initWithRootViewController:decrypt];
    UINavigationController *ne =
        [[UINavigationController alloc] initWithRootViewController:encrypt];
    UINavigationController *nr =
        [[UINavigationController alloc] initWithRootViewController:resign];
    UINavigationController *ng =
        [[UINavigationController alloc] initWithRootViewController:reregion];
    UINavigationController *ni =
        [[UINavigationController alloc] initWithRootViewController:inspect];
    UINavigationController *nu =
        [[UINavigationController alloc] initWithRootViewController:settings];

    UITabBarController *tabs = [UITabBarController new];
    tabs.viewControllers = @[ nd, ne, nr, ng, ni, nu ];
    tabs.tabBar.tintColor = COL_ACCENT;
    tabs.tabBar.unselectedItemTintColor = COL_MUTED;
    return tabs;
}

/* SceneDelegate is referenced only by a string inside Info.plist's
 * UIApplicationSceneManifest — nothing statically links it, so without the
 * constructor anchor above, dead stripping would drop the class and the app
 * would crash at launch. */
@interface SceneDelegate : UIResponder <UIWindowSceneDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation SceneDelegate

/* Runtime lookup by name from Info.plist means nothing references this class
 * statically — anchor it or dead stripping removes it (same as AppDelegate). */
static volatile Class SceneDelegateClassAnchor;
__attribute__((used, constructor)) static void SceneDelegateAnchor(void) {
    SceneDelegateClassAnchor = [SceneDelegate class];
}

- (void)scene:(UIScene *)scene
    willConnectToSession:(UISceneSession *)session
    options:(UISceneConnectionOptions *)connectionOptions {
    UIWindowScene *ws = (UIWindowScene *)scene;
    if (![ws isKindOfClass:[UIWindowScene class]]) return;

    self.window = [[UIWindow alloc] initWithWindowScene:ws];
    self.window.backgroundColor = COL_BG;
    self.window.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    self.window.rootViewController = MakeRootController();
    [self.window makeKeyAndVisible];
}

@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AppDelegate

/* UIApplicationMain looks the delegate up by class name at runtime, so
 * nothing statically references this class — dead stripping would drop it
 * entirely and the app would crash before any UI appears. Constructors are
 * dead-strip roots and the class reference inside anchors the symbol. */
static volatile Class AppDelegateClassAnchor;
__attribute__((used, constructor)) static void AppDelegateAnchor(void) {
    AppDelegateClassAnchor = [AppDelegate class];
}

- (BOOL)application:(UIApplication *)app
    didFinishLaunchingWithOptions:(NSDictionary *)opts {
    [self copyBundledConfig];

    /* Dual-mode launch: with a scene manifest we let SceneDelegate build the
     * window (scene pipeline). Without one — legacy installs like the C test
     * variant — fall back to the classic window path. Main app has the
     * manifest, so this branch stays dormant for it. */
    if (![NSBundle.mainBundle
            objectForInfoDictionaryKey:@"UIApplicationSceneManifest"]) {
        self.window = [[UIWindow alloc] initWithFrame:
            [UIScreen mainScreen].bounds];
        self.window.backgroundColor = COL_BG;
        self.window.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
        self.window.rootViewController = MakeRootController();
        [self.window makeKeyAndVisible];
    }
    return YES;
}

/* Bundle ships a KEYLESS template; only copy when Documents has NO config
 * (the one on the device always wins — keys are user-supplied, never merged
 * or replaced by a newer bundle). */
- (void)copyBundledConfig {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *docs = DocumentsRoot();
    [fm createDirectoryAtPath:docs withIntermediateDirectories:YES
                   attributes:nil error:nil];

    NSString *bundled = nil;
    for (NSBundle *b in [NSBundle allBundles]) {
        NSString *p = [b pathForResource:@"config" ofType:@"ini"];
        if (p) { bundled = p; break; }
    }

   NSString *dst = [docs stringByAppendingPathComponent:@"config.ini"];
    if (bundled && ![[NSFileManager defaultManager] fileExistsAtPath:dst]) {
        [fm copyItemAtPath:bundled toPath:dst error:nil];
    }
}

@end

/* Entry point on iOS is Swift (@main) which calls UIApplicationMain with the
 * delegate class below; this ObjC block is intentionally not present here. */
