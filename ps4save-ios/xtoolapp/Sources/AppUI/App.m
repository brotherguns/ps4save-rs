/* PS4 Save Tool for iOS — native UIKit front-end over the ps4save-rs core.
 * Built and linked by build.sh (no Xcode project needed).
 * Feature parity with the desktop egui GUI: Decrypt, Encrypt, Resign,
 * Reregion, Inspect + keystone / list / check-config / selftest utilities.
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
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
#define COL_BG     PC(24, 24, 24)
#define COL_BG2    PC(31, 31, 31)
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

#pragma mark - Document picker

typedef void (^DocPickBlock)(NSString *path);

/* Lists the app's Documents tree (dirs expand on tap) and calls onPick with a
 * file path (tapped) or folder path (tapped or "Use folder"). Saves reach the
 * app through Files app / iTunes sharing / AirDrop into Documents. */
@interface DocPickerVC : UITableViewController
@property (nonatomic, copy) NSString *currentDir;
@property (nonatomic, copy) NSString *rootDir;
@property (nonatomic, copy) DocPickBlock onPick;
@property (nonatomic, strong) NSMutableArray<NSString *> *dirs;
@property (nonatomic, strong) NSMutableArray<NSString *> *files;
@end

@implementation DocPickerVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.rootDir = [NSString stringWithFormat:@"%@/Documents", NSHomeDirectory()];
    if (!self.currentDir) self.currentDir = self.rootDir;
    if (!self.title) self.title = @"Pick path";

    UIBarButtonItem *use = [[UIBarButtonItem alloc]
        initWithTitle:@"Use folder" style:UIBarButtonItemStylePlain
        target:self action:@selector(useFolder)];
    UIBarButtonItem *mk = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemAdd
        target:self action:@selector(makeFolder)];
    UIBarButtonItem *close = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
        target:self action:@selector(dismissSelf)];
    self.navigationItem.rightBarButtonItems = @[ use, mk ];
    self.navigationItem.leftBarButtonItem = close;
    [self reload];
}

- (void)dismissSelf { [self dismissViewControllerAnimated:YES completion:nil]; }

- (void)useFolder {
    if (self.onPick) self.onPick(self.currentDir);
    [self dismissSelf];
}

- (void)makeFolder {
    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:@"New folder"
                                            message:
        [NSString stringWithFormat:@"in %@/", [self.currentDir lastPathComponent]]
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"folder name";
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
        tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Create"
                                              style:UIAlertActionStyleDefault
        handler:^(UIAlertAction *act) {
            NSString *name = alert.textFields.firstObject.text;
            if (name.length) {
                NSString *dir = [self.currentDir stringByAppendingPathComponent:name];
                [[NSFileManager defaultManager] createDirectoryAtPath:dir
                    withIntermediateDirectories:YES attributes:nil error:nil];
                [self reload];
            }
        }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)reload {
    self.dirs = [NSMutableArray array];
    self.files = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *err = nil;
    NSArray *items = [fm contentsOfDirectoryAtPath:self.currentDir error:&err];
    for (NSString *name in [items sortedArrayUsingSelector:@selector(compare:)]) {
        NSString *full = [self.currentDir stringByAppendingPathComponent:name];
        BOOL isDir = NO;
        if ([fm fileExistsAtPath:full isDirectory:&isDir]) {
            if (isDir) [self.dirs addObject:name];
            else [self.files addObject:name];
        }
    }
    [self.tableView reloadData];
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    return 1 + self.dirs.count + self.files.count; /* row 0 is ".." */
}

- (UITableViewCell *)tableView:(UITableView *)tv
        cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *cell = [tv dequeueReusableCellWithIdentifier:@"cell"];
    if (!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
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
        cell.textLabel.text = [self.dirs[i - 1] stringByAppendingString:@"/"];
        cell.detailTextLabel.text = nil;
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    } else {
        NSString *name = self.files[i - 1 - (NSInteger)self.dirs.count];
        NSString *full = [self.currentDir stringByAppendingPathComponent:name];
        NSDictionary *attr = [[NSFileManager defaultManager]
            attributesOfItemAtPath:full error:nil];
        cell.textLabel.text = name;
        cell.detailTextLabel.text =
            [NSString stringWithFormat:@"%llu B", (unsigned long long)[attr fileSize]];
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
    NSString *pick;
    if (i <= (NSInteger)self.dirs.count) {
        pick = [self.currentDir stringByAppendingPathComponent:self.dirs[i - 1]];
    } else {
        pick = [self.currentDir
            stringByAppendingPathComponent:self.files[i - 1 - (NSInteger)self.dirs.count]];
    }
    if (self.onPick) self.onPick(pick);
    [self dismissSelf];
}

@end

#pragma mark - Command view controller

/* Shared command screen. WHAT rows appear is driven by wants* flags; layout is
 * recomputed in viewDidLayoutSubviews so it follows rotation + safe areas. */
@interface CommandVC : UIViewController <UITextFieldDelegate>
@property (nonatomic, assign) int cmd;      /* ffi command id */
@property (nonatomic, copy) NSString *op;   /* engine key (decrypt/...) */
@property (nonatomic, copy) NSString *runTitle;
@property (nonatomic, assign) BOOL wantsConfig;
@property (nonatomic, assign) BOOL wantsOutput;
@property (nonatomic, assign) BOOL wantsSample;
@property (nonatomic, assign) BOOL wantsAccount;
@property (nonatomic, assign) BOOL needsInput; /* gate on input (default YES) */

@property (nonatomic, strong) UITextField *configField;
@property (nonatomic, strong) UITextField *inputField;
@property (nonatomic, strong) UITextField *sampleField;
@property (nonatomic, strong) UITextField *outputField;
@property (nonatomic, strong) UITextField *accountField;
@property (nonatomic, strong) UIButton *runBtn;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UITextView *outputView;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@end

static const void *kFieldRefKey = &kFieldRefKey;

@implementation CommandVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = COL_BG;
    self.needsInput = YES;

    CGFloat y = 8;
    if (self.wantsConfig)
        [self buildRowFor:@"config" label:@"Cfg:" hint:@"config.ini path" y:&y];
    [self buildRowFor:@"input" label:@"In:" hint:@"save path or folder..." y:&y];
    if (self.wantsSample)
        [self buildRowFor:@"sample" label:@"Sample:" hint:@"target region save..." y:&y];
    if (self.wantsOutput)
        [self buildRowFor:@"output" label:@"Out:" hint:@"output (auto)" y:&y];
    if (self.wantsAccount)
        [self buildRowFor:@"account" label:@"Acct ID:" hint:@"0000000000000000" y:&y];

    self.runBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.runBtn.backgroundColor = COL_ACCENT;
    self.runBtn.layer.cornerRadius = 6;
    self.runBtn.layer.borderColor = COL_BORDER.CGColor;
    self.runBtn.layer.borderWidth = 1;
    [self.runBtn setTitle:self.runTitle ?: self.op forState:UIControlStateNormal];
    [self.runBtn setTitleColor:PC(20, 18, 10) forState:UIControlStateNormal];
    self.runBtn.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    [self.runBtn addTarget:self action:@selector(runTapped)
        forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.runBtn];

    self.statusLabel = [UILabel new];
    self.statusLabel.font = MonoFont(10);
    [self.view addSubview:self.statusLabel];

    self.outputView = [UITextView new];
    self.outputView.backgroundColor = COL_BG2;
    self.outputView.layer.cornerRadius = 4;
    self.outputView.layer.borderColor = COL_BORDER.CGColor;
    self.outputView.layer.borderWidth = 1;
    self.outputView.editable = NO;
    self.outputView.showsVerticalScrollIndicator = YES;
    self.outputView.textContainerInset = UIEdgeInsetsMake(6, 6, 6, 6);
    self.outputView.userInteractionEnabled = YES;
    [self.view addSubview:self.outputView];

    self.spinner = [[UIActivityIndicatorView alloc]
        initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spinner.color = COL_FG;
    [self.view addSubview:self.spinner];

    [self hydrate];
}

/* One labeled row: label + textfield + browse button. */
- (void)buildRowFor:(NSString *)kind label:(NSString *)label hint:(NSString *)hint y:(CGFloat *)y {
    UILabel *l = [UILabel new];
    l.text = label;
    l.textColor = COL_MUTED;
    l.font = MonoFont(11);
    l.tag = [self kindIndexForKind:kind];
    [self.view addSubview:l];

    UITextField *tf = [UITextField new];
    tf.backgroundColor = COL_BG2;
    tf.layer.cornerRadius = 4;
    tf.layer.borderColor = COL_BORDER.CGColor;
    tf.layer.borderWidth = 1;
    tf.placeholder = hint;
    tf.textColor = COL_FG;
    tf.font = MonoFont(11);
    tf.keyboardType = UIKeyboardTypeASCIICapable;
    tf.autocorrectionType = UITextAutocorrectionTypeNo;
    tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tf.returnKeyType = UIReturnKeyDone;
    tf.delegate = self;

    /* keyboard done bar */
    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, [UIScreen mainScreen].bounds.size.width, 36)];
    bar.backgroundColor = COL_BG2;
    UIButton *doneBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    doneBtn.frame = CGRectMake([UIScreen mainScreen].bounds.size.width - 80, 2, 70, 32);
    [doneBtn setTitle:@"Done" forState:UIControlStateNormal];
    [doneBtn setTitleColor:COL_ACCENT forState:UIControlStateNormal];
    [doneBtn addTarget:self action:@selector(dismissKeyboard)
        forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:doneBtn];
    tf.inputAccessoryView = bar;

    /* browse button (remembers which field it belongs to via association) */
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.backgroundColor = COL_BORDER;
    b.layer.cornerRadius = 4;
    [b setTitle:@"..." forState:UIControlStateNormal];
    [b setTitleColor:COL_FG forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    [b addTarget:self action:@selector(browseTapped:)
        forControlEvents:UIControlEventTouchUpInside];

    objc_setAssociatedObject(b, &kFieldRefKey, tf, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [self.view addSubview:tf];
    [self.view addSubview:b];

    if ([kind isEqualToString:@"config"]) self.configField = tf;
    else if ([kind isEqualToString:@"input"]) self.inputField = tf;
    else if ([kind isEqualToString:@"sample"]) self.sampleField = tf;
    else if ([kind isEqualToString:@"output"]) self.outputField = tf;
    else self.accountField = tf;

    *y += 44;
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
    if (self.inputField) [e set:self.op field:@"input" value:self.inputField.text];
    if (self.sampleField) [e set:self.op field:@"sample" value:self.sampleField.text];
    if (self.outputField) [e set:self.op field:@"output" value:self.outputField.text];
    if (self.accountField) [e set:self.op field:@"account" value:self.accountField.text];
}

- (void)hydrate {
    AppEngine *e = [AppEngine shared];
    if (self.configField) self.configField.text = e.configPath;
    if (self.inputField) self.inputField.text = [e get:self.op field:@"input"];
    if (self.sampleField) self.sampleField.text = [e get:self.op field:@"sample"];
    if (self.outputField) self.outputField.text = [e get:self.op field:@"output"];
    if (self.accountField) {
        self.accountField.text = [e get:self.op field:@"account"];
        if (!self.accountField.text.length) self.accountField.text = @"0000000000000000";
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
        y = [self placeRow:0 field:self.configField y:y w:w];
    if (self.inputField)
        y = [self placeRow:1 field:self.inputField y:y w:w];
    if (self.wantsSample && self.sampleField)
        y = [self placeRow:2 field:self.sampleField y:y w:w];
    if (self.wantsOutput && self.outputField)
        y = [self placeRow:3 field:self.outputField y:y w:w];
    if (self.wantsAccount && self.accountField)
        y = [self placeRow:4 field:self.accountField y:y w:w];

    self.runBtn.frame = CGRectMake(12, y + 4, w - 24.0, 42);
    CGFloat sy = y + 46 + 6;
    self.statusLabel.numberOfLines = 2;
    self.statusLabel.frame = CGRectMake(12, sy, w - 24.0, 30);
    CGFloat oy = sy + 36;
    self.outputView.frame = CGRectMake(12, oy, w - 24.0,
        self.view.bounds.size.height - bottom - oy - 8);
    self.spinner.frame = CGRectMake(w - 44, y + 4 + 11, 20, 20);
}

/* Puts label-left, field, browse-right; returns next row's y. */
- (CGFloat)placeRow:(NSInteger)idx field:(UITextField *)tf y:(CGFloat)y w:(CGFloat)w {
    UILabel *l = [self labelWithTag:idx];
    if (l) l.frame = CGRectMake(12, y + 7, 64, 18);
    tf.frame = CGRectMake(76, y, w - 24 - 60 - 38, 32);
    UIButton *b = [self browseForField:tf];
    if (b) b.frame = CGRectMake(w - 12 - 38, y, 38, 32);
    return y + 40;
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

- (UIButton *)browseForField:(UITextField *)tf {
    for (UIView *v in self.view.subviews) {
        if (![v isKindOfClass:[UIButton class]] || v == self.runBtn) continue;
        if (objc_getAssociatedObject(v, &kFieldRefKey) == tf) return (UIButton *)v;
    }
    return nil;
}

- (void)browseTapped:(UIButton *)b {
    UITextField *tf = objc_getAssociatedObject(b, &kFieldRefKey);
    if (!tf) return;
    __weak CommandVC *ws = self;
    DocPickerVC *p = [DocPickerVC new];
    p.onPick = ^(NSString *path) {
        tf.text = path;
        __strong CommandVC *s = ws;
        if (s) [s persist];
    };
    UINavigationController *nav =
        [[UINavigationController alloc] initWithRootViewController:p];
    nav.navigationBar.barStyle = UIBarStyleBlack;
    nav.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    [self presentViewController:nav animated:YES completion:nil];
}

- (void)runTapped {
    [self persist];
    AppEngine *e = [AppEngine shared];
    if (e.busy) return;

    if (self.needsInput && !self.inputField.text.length) {
        [self setStatus:@"error: pick a save first" kind:@"err"];
        return;
    }

    e.busy = YES;
    self.runBtn.enabled = NO;
    self.runBtn.alpha = 0.5;
    [self.spinner startAnimating];
    [self setStatus:@"working..." kind:@"load"];

    NSString *config = e.configPath ?: @"";
    NSString *input = self.inputField.text ?: @"";
    NSString *output = self.outputField.text ?: @"";
    NSString *sample = self.sampleField.text ?: @"";
    NSString *account = self.accountField.text ?: @"";
    int cmd = self.cmd;
    __weak CommandVC *weakself = self;

    dispatch_async(
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            char *raw = ps4save_ios_run(cmd, config.UTF8String, input.UTF8String,
                                        output.UTF8String, sample.UTF8String,
                                        account.UTF8String);
            NSString *text = raw ? [[NSString alloc] initWithUTF8String:raw] : @"";
            if (raw) ps4save_ios_free(raw);
            dispatch_async(dispatch_get_main_queue(), ^{
                __strong CommandVC *s = weakself;
                [AppEngine shared].busy = NO;
                if (!s) return;                /* vc gone: engine already freed */
                s.runBtn.enabled = YES;
                s.runBtn.alpha = 1.0;
                [s.spinner stopAnimating];
                BOOL isErr = [text rangeOfString:@"error"].location != NSNotFound;
                s.outputView.attributedText = AnsiAttributed(text);
                [s setStatus:PlainFirstLine(text)
                        kind:isErr ? @"err" : @"ok"];
            });
        });
}

- (void)setStatus:(NSString *)msg kind:(NSString *)kind {
    if ([kind isEqualToString:@"ok"]) {
        self.statusLabel.textColor = COL_OK;
    } else if ([kind isEqualToString:@"err"]) {
        self.statusLabel.textColor = COL_ERR;
    } else {
        self.statusLabel.textColor = COL_ACCENT;
    }
    self.statusLabel.text = msg;
}

@end

#pragma mark - App delegate

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)app
    didFinishLaunchingWithOptions:(NSDictionary *)opts {
    [self copyBundledConfig];

    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.backgroundColor = COL_BG;

    /* decrypt */
    CommandVC *decrypt = [CommandVC new];
    decrypt.cmd = CMD_DECRYPT;
    decrypt.op = @"decrypt";
    decrypt.runTitle = @"Decrypt";
    decrypt.wantsOutput = YES;
    decrypt.title = @"Decrypt";
    decrypt.tabBarItem.image = [UIImage systemImageNamed:@"lock.open"];

    /* encrypt */
    CommandVC *encrypt = [CommandVC new];
    encrypt.cmd = CMD_ENCRYPT;
    encrypt.op = @"encrypt";
    encrypt.runTitle = @"Encrypt";
    encrypt.wantsOutput = YES;
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
    settings.title = @"Utils";
    settings.tabBarItem.image = [UIImage systemImageNamed:@"gearshape"];

    UITabBarController *tabs = [UITabBarController new];
    tabs.tabBar.barStyle = UIBarStyleBlack;
    tabs.viewControllers = @[ decrypt, encrypt, resign, reregion, inspect, settings ];

    self.window.rootViewController = tabs;
    [self.window makeKeyAndVisible];
    return YES;
}

/* Bundle ships config.ini; on first launch copy it to Documents/config.ini */
- (void)copyBundledConfig {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *docs = [NSString stringWithFormat:@"%@/Documents", NSHomeDirectory()];
    [fm createDirectoryAtPath:docs withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *bundled = [[NSBundle mainBundle] pathForResource:@"config" ofType:@"ini"];
    NSString *dst = [docs stringByAppendingPathComponent:@"config.ini"];
    if (bundled && ![fm fileExistsAtPath:dst]) {
        [fm copyItemAtPath:bundled toPath:dst error:nil];
    }
    /* keep bundled updated when the ipa is newer */
    if (bundled) {
        NSDictionary *b = [fm attributesOfItemAtPath:bundled error:nil];
        NSDictionary *d = [fm attributesOfItemAtPath:dst error:nil];
        NSDate *bd = [b objectForKey:NSFileModificationDate];
        NSDate *dd = [d objectForKey:NSFileModificationDate];
        if (bd && dd && [bd compare:dd] == NSOrderedDescending) {
            [fm removeItemAtPath:dst error:nil];
            [fm copyItemAtPath:bundled toPath:dst error:nil];
        }
    }
}

@end

/* Entry point on iOS is Swift (@main) which calls UIApplicationMain with the
 * delegate class below; this ObjC block is intentionally not present here. */
