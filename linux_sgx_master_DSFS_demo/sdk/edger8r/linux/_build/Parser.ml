type token =
  | EOF
  | TDot
  | TComma
  | TSemicolon
  | TPtr
  | TEqual
  | TLParen
  | TRParen
  | TLBrace
  | TRBrace
  | TLBrack
  | TRBrack
  | Tpublic
  | Tinclude
  | Tconst
  | Tidentifier of (string)
  | Tnumber of (int)
  | Tstring of (string)
  | Tchar
  | Tshort
  | Tunsigned
  | Tint
  | Tfloat
  | Tdouble
  | Tint8
  | Tint16
  | Tint32
  | Tint64
  | Tuint8
  | Tuint16
  | Tuint32
  | Tuint64
  | Tsizet
  | Twchar
  | Tvoid
  | Tlong
  | Tstruct
  | Tunion
  | Tenum
  | Tenclave
  | Tfrom
  | Timport
  | Ttrusted
  | Tuntrusted
  | Tallow
  | Tpropagate_errno

open Parsing;;
let _ = parse_error;;
# 33 "Parser.mly"
open Util				(* for failwithf *)

(* Here we defined some helper routines to check attributes.
 *
 * An alternative approach is to code these rules in Lexer/Parser but
 * it has several drawbacks:
 *
 * 1. Bad extensibility;
 * 2. It grows the table size and down-graded the parsing time;
 * 3. It makes error reporting rigid this way.
 *)

let get_string_from_attr (v: Ast.attr_value) (err_func: int -> string) =
  match v with
      Ast.AString s -> s
    | Ast.ANumber n -> err_func n

(* Check whether 'size' is specified. *)
let has_size (sattr: Ast.ptr_size) =
  sattr.Ast.ps_size <> None
  
(* Check whether 'count' is specified. *)
let has_count (sattr: Ast.ptr_size) =
  sattr.Ast.ps_count <> None

(* Pointers can have the following attributes:
 *
 * 'size'     - specifies the size of the pointer.
 *              e.g. size = 4, size = val ('val' is a parameter);
 *
 * 'count'    - indicates how many of items is managed by the pointer
 *              e.g. count = 100, count = n ('n' is a parameter);
 *
 * 'string'   - indicate the pointer is managing a C string;
 * 'wstring'  - indicate the pointer is managing a wide char string.
 *
 * 'isptr'    - to specify that the foreign type is a pointer.
 * 'isary'    - to specify that the foreign type is an array.
 * 'readonly' - to specify that the foreign type has a 'const' qualifier.
 *
 * 'user_check' - inhibit Edger8r from generating code to check the pointer.
 *
 * 'in'       - the pointer is used as input
 * 'out'      - the pointer is used as output
 *
 * Note that 'size' can be used together with 'count'.
 * 'string' and 'wstring' indicates 'isptr',
 * and they cannot be used with only an 'out' attribute.
 *)
let get_ptr_attr (attr_list: (string * Ast.attr_value) list) =
  let get_new_dir (cds: string) (cda: Ast.ptr_direction) (old: Ast.ptr_direction) =
    if old = Ast.PtrNoDirection then cda
    else if old = Ast.PtrInOut  then failwithf "duplicated attribute: `%s'" cds
    else if old = cda           then failwithf "duplicated attribute: `%s'" cds
    else Ast.PtrInOut
  in
  (* only one 'size' attribute allowed. *)
  let get_new_size (new_value: Ast.attr_value) (old_ptr_size: Ast.ptr_size) =
    if has_size old_ptr_size then
     failwithf "duplicated attribute: `size'"
    else new_value
  in
  (* only one 'count' attribute allowed. *)
  let get_new_count (new_value: Ast.attr_value) (old_ptr_size: Ast.ptr_size) =
    if has_count old_ptr_size then
      failwithf "duplicated attribute: `count'"
    else new_value
  in
  let update_attr (key: string) (value: Ast.attr_value) (res: Ast.ptr_attr) =
    match key with
        "size"     ->
        { res with Ast.pa_size = { res.Ast.pa_size with Ast.ps_size  = Some(get_new_size value res.Ast.pa_size)}}
      | "count"    ->
        { res with Ast.pa_size = { res.Ast.pa_size with Ast.ps_count = Some(get_new_count value res.Ast.pa_size)}}
      | "sizefunc" ->
        failwithf "The attribute 'sizefunc' is deprecated. Please use 'size' attribute instead."
      | "string"  -> { res with Ast.pa_isstr = true; }
      | "wstring" -> { res with Ast.pa_iswstr = true; }
      | "isptr"   -> { res with Ast.pa_isptr = true }
      | "isary"   -> { res with Ast.pa_isary = true }

      | "readonly" -> { res with Ast.pa_rdonly = true }
      | "user_check" -> { res with Ast.pa_chkptr = false }

      | "in"  ->
        let newdir = get_new_dir "in"  Ast.PtrIn  res.Ast.pa_direction
        in { res with Ast.pa_direction = newdir }
      | "out" ->
        let newdir = get_new_dir "out" Ast.PtrOut res.Ast.pa_direction
        in { res with Ast.pa_direction = newdir }
      | _ -> failwithf "unknown attribute: %s" key
  in
  let rec do_get_ptr_attr alist res_attr =
    match alist with
        [] -> res_attr
      | (k,v) :: xs -> do_get_ptr_attr xs (update_attr k v res_attr)
  in
  let has_str_attr (pattr: Ast.ptr_attr) =
    if pattr.Ast.pa_isstr && pattr.Ast.pa_iswstr
    then failwith "`string' and `wstring' are mutual exclusive"
    else (pattr.Ast.pa_isstr || pattr.Ast.pa_iswstr)
  in
  let check_invalid_ptr_size (pattr: Ast.ptr_attr) =
    let ps = pattr.Ast.pa_size in
      if ps <> Ast.empty_ptr_size && has_str_attr pattr
      then failwith "size attributes are mutual exclusive with (w)string attribute"
      else
        if (ps <> Ast.empty_ptr_size || has_str_attr pattr) &&
          pattr.Ast.pa_direction = Ast.PtrNoDirection
        then failwith "size/string attributes must be used with pointer direction"
        else pattr
  in
  let check_ptr_dir (pattr: Ast.ptr_attr) =
    if pattr.Ast.pa_direction <> Ast.PtrNoDirection && pattr.Ast.pa_chkptr = false
    then failwith "pointer direction and `user_check' are mutual exclusive"
    else
      if pattr.Ast.pa_direction = Ast.PtrNoDirection && pattr.Ast.pa_chkptr
      then failwith "pointer/array should have direction attribute or `user_check'"
      else
        if pattr.Ast.pa_direction = Ast.PtrOut && has_str_attr pattr
        then failwith "string/wstring should be used with an `in' attribute"
        else pattr
  in
  let check_invalid_ary_attr (pattr: Ast.ptr_attr) =
    if pattr.Ast.pa_size <> Ast.empty_ptr_size
    then failwith "Pointer size attributes cannot be used with foreign array"
    else
      if not pattr.Ast.pa_isptr
      then
        (* 'pa_chkptr' is default to true unless user specifies 'user_check' *)
        if pattr.Ast.pa_chkptr && pattr.Ast.pa_direction = Ast.PtrNoDirection
        then failwith "array must have direction attribute or `user_check'"
        else pattr
      else
        if has_str_attr pattr
        then failwith "`isary' cannot be used with `string/wstring' together"
        else failwith "`isary' cannot be used with `isptr' together"
  in
  let pattr = do_get_ptr_attr attr_list { Ast.pa_direction = Ast.PtrNoDirection;
                                          Ast.pa_size = Ast.empty_ptr_size;
                                          Ast.pa_isptr = false;
                                          Ast.pa_isary = false;
                                          Ast.pa_isstr = false;
                                          Ast.pa_iswstr = false;
                                          Ast.pa_rdonly = false;
                                          Ast.pa_chkptr = true;
                                        }
  in
    if pattr.Ast.pa_isary
    then check_invalid_ary_attr pattr
    else check_invalid_ptr_size pattr |> check_ptr_dir

(* Untrusted functions can have these attributes:
 *
 * a. 3 mutual exclusive calling convention specifier:
 *     'stdcall', 'fastcall', 'cdecl'.
 *
 * b. 'dllimport' - to import a public symbol.
 *)
let get_func_attr (attr_list: (string * Ast.attr_value) list) =
  let get_new_callconv (key: string) (cur: Ast.call_conv) (old: Ast.call_conv) =
    if old <> Ast.CC_NONE then
      failwithf "unexpected `%s',  conflict with `%s'." key (Ast.get_call_conv_str old)
    else cur
  in
  let update_attr (key: string) (value: Ast.attr_value) (res: Ast.func_attr) =
    match key with
    | "stdcall"  ->
      let callconv = get_new_callconv key Ast.CC_STDCALL res.Ast.fa_convention
      in { res with Ast.fa_convention = callconv}
    | "fastcall" ->
      let callconv = get_new_callconv key Ast.CC_FASTCALL res.Ast.fa_convention
      in { res with Ast.fa_convention = callconv}
    | "cdecl"    ->
      let callconv = get_new_callconv key Ast.CC_CDECL res.Ast.fa_convention
      in { res with Ast.fa_convention = callconv}
    | "dllimport" ->
      if res.Ast.fa_dllimport then failwith "duplicated attribute: `dllimport'"
      else { res with Ast.fa_dllimport = true }
    | _ -> failwithf "invalid function attribute: %s" key
  in
  let rec do_get_func_attr alist res_attr =
    match alist with
      [] -> res_attr
    | (k,v) :: xs -> do_get_func_attr xs (update_attr k v res_attr)
  in do_get_func_attr attr_list { Ast.fa_dllimport = false;
                                  Ast.fa_convention= Ast.CC_NONE;
                                }

(* Some syntax checking against pointer attributes.
 * range: (Lexing.position * Lexing.position)
 *)
let check_ptr_attr (fd: Ast.func_decl) range =
  let fname = fd.Ast.fname in
  let check_const (pattr: Ast.ptr_attr) (identifier: string) =
    let raise_err_direction (direction:string) =
      failwithf "`%s': `%s' is readonly - cannot be used with `%s'"
        fname identifier direction
    in
      if pattr.Ast.pa_rdonly
      then
        match pattr.Ast.pa_direction with
            Ast.PtrOut | Ast.PtrInOut -> raise_err_direction "out"
          | _ -> ()
      else ()
  in
  let check_void_ptr_size (pattr: Ast.ptr_attr) (identifier: string) =
    if pattr.Ast.pa_chkptr && (not (has_size pattr.Ast.pa_size))
    then failwithf "`%s': void pointer `%s' - buffer size unknown" fname identifier
    else ()
  in
  let check_string_ptr_size (atype: Ast.atype) (pattr: Ast.ptr_attr) (identifier: string) =
    if (pattr.Ast.pa_isstr)
    then
      match atype with
      Ast.Ptr(Ast.Char(_)) -> ()
      | _ -> failwithf "`%s': invalid 'string' attribute - `%s' is not char pointer." fname identifier
    else
      if (atype <> Ast.Ptr(Ast.WChar) &&  pattr.Ast.pa_iswstr)
      then failwithf "`%s': invalid 'wstring' attribute - `%s' is not wchar_t pointer." fname identifier
      else ()
  in
  let check_array_dims (atype: Ast.atype) (pattr: Ast.ptr_attr) (declr: Ast.declarator) =
    if Ast.is_array declr then
      if has_size pattr.Ast.pa_size then
        failwithf "`%s': invalid 'size' attribute - `%s' is explicitly declared array." fname declr.Ast.identifier
      else if has_count pattr.Ast.pa_size then
        failwithf "`%s': invalid 'count' attribute - `%s' is explicitly declared array." fname declr.Ast.identifier
      else if pattr.Ast.pa_isary then
        failwithf "`%s': invalid 'isary' attribute - `%s' is explicitly declared array." fname declr.Ast.identifier
    else ()
  in
  let check_pointer_array (atype: Ast.atype) (pattr: Ast.ptr_attr) (declr: Ast.declarator) = 
    let is_ary = (Ast.is_array declr || pattr.Ast.pa_isary) in
    let is_ptr  =
      match atype with
        Ast.Ptr _ -> true
      | _         -> pattr.Ast.pa_isptr
    in
    if is_ary && is_ptr then
      failwithf "`%s': Pointer array not allowed - `%s' is a pointer array." fname declr.Ast.identifier 
    else ()
  in
  let checker (pd: Ast.pdecl) =
    let pt, declr = pd in
    let identifier = declr.Ast.identifier in
      match pt with
          Ast.PTVal _ -> ()
        | Ast.PTPtr(atype, pattr) ->
          if atype = Ast.Ptr(Ast.Void) then (* 'void' pointer, check there is a size or 'user_check' *)
            check_void_ptr_size pattr identifier
          else
            check_pointer_array atype pattr declr;
            check_const pattr identifier;
            check_string_ptr_size atype pattr identifier;
            check_array_dims atype pattr declr
  in
    List.iter checker fd.Ast.plist
# 311 "Parser.ml"
let yytransl_const = [|
    0 (* EOF *);
  257 (* TDot *);
  258 (* TComma *);
  259 (* TSemicolon *);
  260 (* TPtr *);
  261 (* TEqual *);
  262 (* TLParen *);
  263 (* TRParen *);
  264 (* TLBrace *);
  265 (* TRBrace *);
  266 (* TLBrack *);
  267 (* TRBrack *);
  268 (* Tpublic *);
  269 (* Tinclude *);
  270 (* Tconst *);
  274 (* Tchar *);
  275 (* Tshort *);
  276 (* Tunsigned *);
  277 (* Tint *);
  278 (* Tfloat *);
  279 (* Tdouble *);
  280 (* Tint8 *);
  281 (* Tint16 *);
  282 (* Tint32 *);
  283 (* Tint64 *);
  284 (* Tuint8 *);
  285 (* Tuint16 *);
  286 (* Tuint32 *);
  287 (* Tuint64 *);
  288 (* Tsizet *);
  289 (* Twchar *);
  290 (* Tvoid *);
  291 (* Tlong *);
  292 (* Tstruct *);
  293 (* Tunion *);
  294 (* Tenum *);
  295 (* Tenclave *);
  296 (* Tfrom *);
  297 (* Timport *);
  298 (* Ttrusted *);
  299 (* Tuntrusted *);
  300 (* Tallow *);
  301 (* Tpropagate_errno *);
    0|]

let yytransl_block = [|
  271 (* Tidentifier *);
  272 (* Tnumber *);
  273 (* Tstring *);
    0|]

let yylhs = "\255\255\
\002\000\002\000\003\000\003\000\004\000\004\000\005\000\005\000\
\006\000\006\000\006\000\006\000\006\000\007\000\007\000\007\000\
\007\000\007\000\007\000\007\000\007\000\007\000\007\000\007\000\
\007\000\007\000\007\000\007\000\007\000\007\000\007\000\007\000\
\007\000\011\000\011\000\012\000\013\000\014\000\014\000\015\000\
\015\000\015\000\016\000\016\000\017\000\017\000\018\000\018\000\
\018\000\018\000\019\000\019\000\020\000\020\000\021\000\021\000\
\021\000\008\000\009\000\010\000\022\000\024\000\025\000\025\000\
\026\000\026\000\027\000\027\000\028\000\028\000\028\000\029\000\
\029\000\029\000\023\000\023\000\030\000\031\000\031\000\032\000\
\033\000\033\000\034\000\035\000\035\000\036\000\036\000\037\000\
\037\000\038\000\038\000\041\000\041\000\039\000\039\000\040\000\
\040\000\042\000\042\000\044\000\044\000\044\000\045\000\045\000\
\046\000\047\000\047\000\043\000\043\000\048\000\048\000\048\000\
\049\000\049\000\049\000\049\000\049\000\050\000\001\000\000\000"

let yylen = "\002\000\
\001\000\002\000\001\000\001\000\002\000\003\000\000\000\001\000\
\002\000\003\000\002\000\001\000\001\000\001\000\001\000\001\000\
\001\000\002\000\001\000\001\000\001\000\001\000\001\000\001\000\
\001\000\001\000\001\000\001\000\001\000\001\000\001\000\001\000\
\001\000\001\000\002\000\002\000\003\000\001\000\002\000\001\000\
\001\000\002\000\001\000\002\000\001\000\002\000\002\000\001\000\
\004\000\003\000\002\000\003\000\001\000\003\000\003\000\003\000\
\001\000\002\000\002\000\002\000\004\000\004\000\004\000\004\000\
\000\000\001\000\001\000\003\000\001\000\003\000\003\000\001\000\
\001\000\001\000\002\000\003\000\002\000\001\000\003\000\001\000\
\004\000\004\000\002\000\001\000\002\000\005\000\005\000\001\000\
\002\000\001\000\002\000\000\000\001\000\000\000\004\000\000\000\
\003\000\003\000\004\000\002\000\003\000\003\000\001\000\003\000\
\002\000\000\000\001\000\004\000\003\000\000\000\003\000\004\000\
\000\000\002\000\003\000\003\000\002\000\004\000\003\000\002\000"

let yydefred = "\000\000\
\000\000\000\000\000\000\120\000\000\000\113\000\000\000\000\000\
\119\000\118\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\072\000\073\000\074\000\000\000\
\000\000\114\000\117\000\083\000\058\000\059\000\000\000\060\000\
\080\000\000\000\000\000\000\000\000\000\000\000\000\000\116\000\
\115\000\000\000\000\000\000\000\067\000\000\000\084\000\000\000\
\000\000\000\000\000\000\000\000\000\000\033\000\001\000\003\000\
\000\000\016\000\017\000\019\000\020\000\021\000\022\000\023\000\
\024\000\025\000\026\000\027\000\028\000\029\000\000\000\000\000\
\014\000\000\000\012\000\000\000\015\000\000\000\030\000\031\000\
\032\000\000\000\000\000\000\000\000\000\000\000\000\000\063\000\
\000\000\082\000\078\000\000\000\085\000\000\000\000\000\093\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\002\000\000\000\008\000\000\000\018\000\005\000\009\000\034\000\
\000\000\000\000\077\000\061\000\000\000\075\000\062\000\064\000\
\070\000\071\000\068\000\000\000\086\000\000\000\087\000\051\000\
\000\000\000\000\053\000\000\000\000\000\000\000\038\000\000\000\
\000\000\000\000\000\000\000\000\097\000\006\000\010\000\035\000\
\046\000\076\000\079\000\095\000\000\000\000\000\052\000\036\000\
\000\000\000\000\098\000\000\000\000\000\039\000\000\000\000\000\
\000\000\107\000\109\000\055\000\056\000\054\000\037\000\100\000\
\000\000\000\000\048\000\000\000\000\000\000\000\103\000\099\000\
\108\000\111\000\000\000\000\000\101\000\105\000\000\000\047\000\
\000\000\102\000\112\000\000\000\000\000\104\000\000\000"

let yydgoto = "\002\000\
\004\000\073\000\074\000\075\000\076\000\077\000\078\000\079\000\
\080\000\081\000\113\000\134\000\135\000\136\000\137\000\082\000\
\115\000\172\000\102\000\130\000\131\000\021\000\083\000\022\000\
\023\000\043\000\044\000\045\000\024\000\084\000\092\000\034\000\
\025\000\047\000\048\000\027\000\049\000\052\000\050\000\053\000\
\097\000\103\000\104\000\155\000\174\000\175\000\163\000\140\000\
\008\000\005\000"

let yysindex = "\049\000\
\227\254\000\000\079\255\000\000\087\255\000\000\126\000\249\254\
\000\000\000\000\142\255\174\255\200\255\077\255\201\255\211\255\
\013\000\021\000\041\000\042\000\000\000\000\000\000\000\045\000\
\048\000\000\000\000\000\000\000\000\000\000\000\038\000\000\000\
\000\000\017\000\065\000\065\000\245\254\245\254\038\000\000\000\
\000\000\074\000\107\000\052\000\000\000\241\255\000\000\065\000\
\111\000\071\000\065\000\112\000\037\000\000\000\000\000\000\000\
\022\255\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\019\255\091\000\
\000\000\000\000\000\000\101\000\000\000\120\000\000\000\000\000\
\000\000\110\000\080\255\123\000\235\255\118\000\172\255\000\000\
\038\000\000\000\000\000\127\000\000\000\071\000\125\000\000\000\
\245\254\037\000\128\000\147\255\176\255\245\254\086\000\129\000\
\000\000\100\000\000\000\113\000\000\000\000\000\000\000\000\000\
\132\000\130\000\000\000\000\000\134\000\000\000\000\000\000\000\
\000\000\000\000\000\000\124\000\000\000\135\000\000\000\000\000\
\136\000\051\255\000\000\206\255\137\000\138\000\000\000\138\000\
\131\000\086\000\139\000\088\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\233\255\140\000\000\000\000\000\
\133\000\041\255\000\000\141\000\138\000\000\000\137\000\088\000\
\114\255\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\245\254\142\000\000\000\110\000\062\000\214\255\000\000\000\000\
\000\000\000\000\244\255\120\000\000\000\000\000\245\254\000\000\
\008\000\000\000\000\000\132\000\120\000\000\000\132\000"

let yyrindex = "\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\143\000\000\000\
\000\000\000\000\115\255\145\255\121\000\121\000\143\000\000\000\
\000\000\183\255\000\000\144\000\000\000\000\000\000\000\115\255\
\000\000\175\255\145\255\000\000\072\255\000\000\000\000\000\000\
\076\255\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\097\000\000\000\
\000\000\098\000\000\000\000\000\000\000\237\255\000\000\000\000\
\000\000\000\000\121\000\000\000\121\000\000\000\000\000\000\000\
\000\000\000\000\000\000\147\000\000\000\205\255\000\000\000\000\
\121\000\073\255\000\000\000\000\000\000\121\000\002\255\000\000\
\000\000\097\000\000\000\024\255\000\000\000\000\000\000\000\000\
\009\000\154\255\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\117\255\000\000\000\000\000\000\000\000\081\255\000\000\102\000\
\000\000\002\255\000\000\148\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\121\000\000\000\000\000\108\000\000\000\000\000\148\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\121\000\099\000\000\000\000\000\121\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\121\000\000\000\
\121\000\000\000\000\000\145\000\000\000\000\000\146\000"

let yygindex = "\000\000\
\000\000\000\000\090\001\000\000\097\001\000\000\125\255\148\001\
\150\001\151\001\198\255\000\000\157\255\028\001\049\001\203\255\
\248\000\000\000\103\255\000\000\015\001\000\000\128\001\000\000\
\000\000\129\001\000\000\078\001\000\000\040\000\008\001\000\000\
\000\000\251\255\134\001\000\000\000\000\000\000\123\001\121\001\
\000\000\179\000\000\000\014\001\000\000\245\000\016\001\037\001\
\000\000\000\000"

let yytablesize = 432
let yytable = "\101\000\
\173\000\010\000\026\000\054\000\110\000\011\000\055\000\056\000\
\057\000\003\000\058\000\059\000\060\000\061\000\062\000\063\000\
\064\000\065\000\066\000\067\000\068\000\069\000\070\000\071\000\
\012\000\013\000\072\000\011\000\012\000\013\000\014\000\173\000\
\015\000\011\000\016\000\017\000\158\000\180\000\011\000\105\000\
\056\000\109\000\093\000\101\000\101\000\093\000\110\000\168\000\
\101\000\001\000\100\000\189\000\150\000\110\000\169\000\054\000\
\106\000\158\000\055\000\056\000\057\000\151\000\058\000\059\000\
\060\000\061\000\062\000\063\000\064\000\065\000\066\000\067\000\
\068\000\069\000\170\000\071\000\012\000\013\000\072\000\007\000\
\090\000\091\000\041\000\041\000\031\000\007\000\006\000\041\000\
\116\000\007\000\007\000\032\000\007\000\007\000\054\000\041\000\
\007\000\055\000\056\000\057\000\171\000\058\000\059\000\060\000\
\061\000\062\000\063\000\064\000\065\000\066\000\067\000\068\000\
\069\000\070\000\071\000\012\000\013\000\072\000\057\000\184\000\
\178\000\188\000\117\000\094\000\117\000\009\000\094\000\057\000\
\091\000\094\000\191\000\171\000\094\000\094\000\094\000\094\000\
\094\000\094\000\094\000\094\000\094\000\094\000\094\000\094\000\
\094\000\094\000\094\000\094\000\094\000\094\000\094\000\094\000\
\094\000\096\000\096\000\045\000\045\000\128\000\028\000\096\000\
\045\000\129\000\096\000\096\000\096\000\096\000\096\000\096\000\
\096\000\096\000\096\000\096\000\096\000\096\000\096\000\096\000\
\096\000\096\000\096\000\096\000\096\000\096\000\096\000\088\000\
\069\000\132\000\121\000\122\000\029\000\092\000\133\000\069\000\
\092\000\092\000\092\000\092\000\092\000\092\000\092\000\092\000\
\092\000\092\000\092\000\092\000\092\000\092\000\092\000\092\000\
\092\000\092\000\092\000\092\000\092\000\089\000\030\000\185\000\
\152\000\033\000\035\000\092\000\186\000\153\000\092\000\092\000\
\092\000\092\000\092\000\092\000\092\000\092\000\092\000\092\000\
\092\000\092\000\092\000\092\000\092\000\092\000\092\000\092\000\
\092\000\092\000\092\000\119\000\090\000\124\000\043\000\164\000\
\165\000\054\000\187\000\043\000\055\000\056\000\057\000\091\000\
\058\000\059\000\060\000\061\000\062\000\063\000\064\000\065\000\
\066\000\067\000\068\000\069\000\070\000\071\000\012\000\013\000\
\072\000\100\000\044\000\126\000\036\000\169\000\054\000\044\000\
\138\000\055\000\056\000\057\000\037\000\058\000\059\000\060\000\
\061\000\062\000\063\000\064\000\065\000\066\000\067\000\068\000\
\069\000\070\000\071\000\012\000\013\000\072\000\100\000\040\000\
\038\000\039\000\041\000\054\000\042\000\089\000\055\000\056\000\
\057\000\046\000\058\000\059\000\060\000\061\000\062\000\063\000\
\064\000\065\000\066\000\067\000\068\000\069\000\070\000\071\000\
\012\000\013\000\072\000\183\000\054\000\011\000\087\000\055\000\
\056\000\057\000\096\000\058\000\059\000\060\000\061\000\062\000\
\063\000\064\000\065\000\066\000\067\000\068\000\069\000\070\000\
\071\000\012\000\013\000\072\000\004\000\013\000\029\000\040\000\
\040\000\032\000\004\000\013\000\040\000\042\000\042\000\004\000\
\013\000\029\000\042\000\088\000\040\000\004\000\008\000\095\000\
\099\000\111\000\042\000\112\000\114\000\118\000\120\000\125\000\
\124\000\139\000\127\000\141\000\162\000\143\000\142\000\144\000\
\146\000\148\000\147\000\132\000\149\000\007\000\154\000\167\000\
\161\000\159\000\107\000\156\000\181\000\081\000\106\000\065\000\
\066\000\108\000\129\000\018\000\153\000\019\000\020\000\050\000\
\049\000\157\000\145\000\182\000\166\000\085\000\123\000\086\000\
\179\000\051\000\094\000\098\000\176\000\190\000\160\000\177\000"

let yycheck = "\053\000\
\154\000\009\001\008\000\015\001\003\001\013\001\018\001\019\001\
\020\001\039\001\022\001\023\001\024\001\025\001\026\001\027\001\
\028\001\029\001\030\001\031\001\032\001\033\001\034\001\035\001\
\036\001\037\001\038\001\004\001\036\001\037\001\038\001\185\000\
\040\001\010\001\042\001\043\001\136\000\169\000\015\001\018\001\
\019\001\023\001\048\000\097\000\098\000\051\000\045\001\007\001\
\102\000\001\000\010\001\183\000\002\001\035\001\014\001\015\001\
\035\001\157\000\018\001\019\001\020\001\011\001\022\001\023\001\
\024\001\025\001\026\001\027\001\028\001\029\001\030\001\031\001\
\032\001\033\001\034\001\035\001\036\001\037\001\038\001\004\001\
\009\001\009\001\002\001\003\001\008\001\010\001\008\001\007\001\
\009\001\003\001\015\001\015\001\021\001\021\001\015\001\015\001\
\021\001\018\001\019\001\020\001\154\000\022\001\023\001\024\001\
\025\001\026\001\027\001\028\001\029\001\030\001\031\001\032\001\
\033\001\034\001\035\001\036\001\037\001\038\001\002\001\173\000\
\007\001\180\000\083\000\009\001\085\000\000\000\012\001\011\001\
\015\001\015\001\189\000\185\000\018\001\019\001\020\001\021\001\
\022\001\023\001\024\001\025\001\026\001\027\001\028\001\029\001\
\030\001\031\001\032\001\033\001\034\001\035\001\036\001\037\001\
\038\001\009\001\010\001\002\001\003\001\011\001\017\001\015\001\
\007\001\015\001\018\001\019\001\020\001\021\001\022\001\023\001\
\024\001\025\001\026\001\027\001\028\001\029\001\030\001\031\001\
\032\001\033\001\034\001\035\001\036\001\037\001\038\001\009\001\
\002\001\010\001\015\001\016\001\015\001\015\001\015\001\009\001\
\018\001\019\001\020\001\021\001\022\001\023\001\024\001\025\001\
\026\001\027\001\028\001\029\001\030\001\031\001\032\001\033\001\
\034\001\035\001\036\001\037\001\038\001\009\001\015\001\002\001\
\011\001\017\001\008\001\015\001\007\001\016\001\018\001\019\001\
\020\001\021\001\022\001\023\001\024\001\025\001\026\001\027\001\
\028\001\029\001\030\001\031\001\032\001\033\001\034\001\035\001\
\036\001\037\001\038\001\009\001\004\001\002\001\010\001\015\001\
\016\001\015\001\007\001\015\001\018\001\019\001\020\001\015\001\
\022\001\023\001\024\001\025\001\026\001\027\001\028\001\029\001\
\030\001\031\001\032\001\033\001\034\001\035\001\036\001\037\001\
\038\001\010\001\010\001\097\000\008\001\014\001\015\001\015\001\
\102\000\018\001\019\001\020\001\008\001\022\001\023\001\024\001\
\025\001\026\001\027\001\028\001\029\001\030\001\031\001\032\001\
\033\001\034\001\035\001\036\001\037\001\038\001\010\001\003\001\
\008\001\008\001\003\001\015\001\015\001\002\001\018\001\019\001\
\020\001\041\001\022\001\023\001\024\001\025\001\026\001\027\001\
\028\001\029\001\030\001\031\001\032\001\033\001\034\001\035\001\
\036\001\037\001\038\001\014\001\015\001\013\001\005\001\018\001\
\019\001\020\001\012\001\022\001\023\001\024\001\025\001\026\001\
\027\001\028\001\029\001\030\001\031\001\032\001\033\001\034\001\
\035\001\036\001\037\001\038\001\004\001\004\001\004\001\002\001\
\003\001\015\001\010\001\010\001\007\001\002\001\003\001\015\001\
\015\001\015\001\007\001\009\001\015\001\021\001\021\001\009\001\
\009\001\021\001\015\001\004\001\015\001\003\001\009\001\003\001\
\002\001\044\001\003\001\003\001\045\001\021\001\035\001\004\001\
\003\001\003\001\015\001\010\001\005\001\021\001\006\001\011\001\
\006\001\015\001\057\000\010\001\007\001\003\001\003\001\009\001\
\009\001\057\000\015\001\008\000\016\001\008\000\008\000\015\001\
\015\001\134\000\114\000\172\000\150\000\038\000\089\000\039\000\
\161\000\036\000\048\000\051\000\159\000\185\000\138\000\160\000"

let yynames_const = "\
  EOF\000\
  TDot\000\
  TComma\000\
  TSemicolon\000\
  TPtr\000\
  TEqual\000\
  TLParen\000\
  TRParen\000\
  TLBrace\000\
  TRBrace\000\
  TLBrack\000\
  TRBrack\000\
  Tpublic\000\
  Tinclude\000\
  Tconst\000\
  Tchar\000\
  Tshort\000\
  Tunsigned\000\
  Tint\000\
  Tfloat\000\
  Tdouble\000\
  Tint8\000\
  Tint16\000\
  Tint32\000\
  Tint64\000\
  Tuint8\000\
  Tuint16\000\
  Tuint32\000\
  Tuint64\000\
  Tsizet\000\
  Twchar\000\
  Tvoid\000\
  Tlong\000\
  Tstruct\000\
  Tunion\000\
  Tenum\000\
  Tenclave\000\
  Tfrom\000\
  Timport\000\
  Ttrusted\000\
  Tuntrusted\000\
  Tallow\000\
  Tpropagate_errno\000\
  "

let yynames_block = "\
  Tidentifier\000\
  Tnumber\000\
  Tstring\000\
  "

let yyact = [|
  (fun _ -> failwith "parser")
; (fun __caml_parser_env ->
    Obj.repr(
# 319 "Parser.mly"
                 ( Ast.Char Ast.Signed )
# 665 "Parser.ml"
               : 'char_type))
; (fun __caml_parser_env ->
    Obj.repr(
# 320 "Parser.mly"
                    ( Ast.Char Ast.Unsigned )
# 671 "Parser.ml"
               : 'char_type))
; (fun __caml_parser_env ->
    Obj.repr(
# 324 "Parser.mly"
                     ( Ast.IShort )
# 677 "Parser.ml"
               : 'ex_shortness))
; (fun __caml_parser_env ->
    Obj.repr(
# 325 "Parser.mly"
          ( Ast.ILong )
# 683 "Parser.ml"
               : 'ex_shortness))
; (fun __caml_parser_env ->
    Obj.repr(
# 328 "Parser.mly"
                          ( Ast.LLong Ast.Signed )
# 689 "Parser.ml"
               : 'longlong))
; (fun __caml_parser_env ->
    Obj.repr(
# 329 "Parser.mly"
                          ( Ast.LLong Ast.Unsigned )
# 695 "Parser.ml"
               : 'longlong))
; (fun __caml_parser_env ->
    Obj.repr(
# 331 "Parser.mly"
                       ( Ast.INone )
# 701 "Parser.ml"
               : 'shortness))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'ex_shortness) in
    Obj.repr(
# 332 "Parser.mly"
                 ( _1 )
# 708 "Parser.ml"
               : 'shortness))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'shortness) in
    Obj.repr(
# 335 "Parser.mly"
                         (
      Ast.Int { Ast.ia_signedness = Ast.Signed; Ast.ia_shortness = _1 }
    )
# 717 "Parser.ml"
               : 'int_type))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'shortness) in
    Obj.repr(
# 338 "Parser.mly"
                             (
      Ast.Int { Ast.ia_signedness = Ast.Unsigned; Ast.ia_shortness = _2 }
    )
# 726 "Parser.ml"
               : 'int_type))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'shortness) in
    Obj.repr(
# 341 "Parser.mly"
                        (
      Ast.Int { Ast.ia_signedness = Ast.Unsigned; Ast.ia_shortness = _2 }
    )
# 735 "Parser.ml"
               : 'int_type))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'longlong) in
    Obj.repr(
# 344 "Parser.mly"
             ( _1 )
# 742 "Parser.ml"
               : 'int_type))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'ex_shortness) in
    Obj.repr(
# 345 "Parser.mly"
                 (
      Ast.Int { Ast.ia_signedness = Ast.Signed; Ast.ia_shortness = _1 }
    )
# 751 "Parser.ml"
               : 'int_type))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'char_type) in
    Obj.repr(
# 351 "Parser.mly"
              ( _1 )
# 758 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'int_type) in
    Obj.repr(
# 352 "Parser.mly"
              ( _1 )
# 765 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 354 "Parser.mly"
             ( Ast.Float )
# 771 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 355 "Parser.mly"
             ( Ast.Double )
# 777 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 356 "Parser.mly"
                  ( Ast.LDouble )
# 783 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 358 "Parser.mly"
             ( Ast.Int8 )
# 789 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 359 "Parser.mly"
             ( Ast.Int16 )
# 795 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 360 "Parser.mly"
             ( Ast.Int32 )
# 801 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 361 "Parser.mly"
             ( Ast.Int64 )
# 807 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 362 "Parser.mly"
             ( Ast.UInt8 )
# 813 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 363 "Parser.mly"
             ( Ast.UInt16 )
# 819 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 364 "Parser.mly"
             ( Ast.UInt32 )
# 825 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 365 "Parser.mly"
             ( Ast.UInt64 )
# 831 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 366 "Parser.mly"
             ( Ast.SizeT )
# 837 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 367 "Parser.mly"
             ( Ast.WChar )
# 843 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 368 "Parser.mly"
             ( Ast.Void )
# 849 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'struct_specifier) in
    Obj.repr(
# 370 "Parser.mly"
                     ( _1 )
# 856 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'union_specifier) in
    Obj.repr(
# 371 "Parser.mly"
                     ( _1 )
# 863 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'enum_specifier) in
    Obj.repr(
# 372 "Parser.mly"
                     ( _1 )
# 870 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 373 "Parser.mly"
                     ( Ast.Foreign(_1) )
# 877 "Parser.ml"
               : 'type_spec))
; (fun __caml_parser_env ->
    Obj.repr(
# 376 "Parser.mly"
                 ( fun ii -> Ast.Ptr(ii) )
# 883 "Parser.ml"
               : 'pointer))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'pointer) in
    Obj.repr(
# 377 "Parser.mly"
                 ( fun ii -> Ast.Ptr(_1 ii) )
# 890 "Parser.ml"
               : 'pointer))
; (fun __caml_parser_env ->
    Obj.repr(
# 380 "Parser.mly"
                                         ( failwith "Flexible array is not supported." )
# 896 "Parser.ml"
               : 'empty_dimension))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 1 : int) in
    Obj.repr(
# 381 "Parser.mly"
                                         ( if _2 <> 0 then [_2]
                                           else failwith "Zero-length array is not supported." )
# 904 "Parser.ml"
               : 'fixed_dimension))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'fixed_dimension) in
    Obj.repr(
# 384 "Parser.mly"
                                     ( _1 )
# 911 "Parser.ml"
               : 'fixed_size_array))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'fixed_size_array) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'fixed_dimension) in
    Obj.repr(
# 385 "Parser.mly"
                                     ( _1 @ _2 )
# 919 "Parser.ml"
               : 'fixed_size_array))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'fixed_size_array) in
    Obj.repr(
# 388 "Parser.mly"
                                     ( _1 )
# 926 "Parser.ml"
               : 'array_size))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'empty_dimension) in
    Obj.repr(
# 389 "Parser.mly"
                                     ( _1 )
# 933 "Parser.ml"
               : 'array_size))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'empty_dimension) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'fixed_size_array) in
    Obj.repr(
# 390 "Parser.mly"
                                     ( _1 @ _2 )
# 941 "Parser.ml"
               : 'array_size))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'type_spec) in
    Obj.repr(
# 393 "Parser.mly"
                      ( _1 )
# 948 "Parser.ml"
               : 'all_type))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'type_spec) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'pointer) in
    Obj.repr(
# 394 "Parser.mly"
                      ( _2 _1 )
# 956 "Parser.ml"
               : 'all_type))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 397 "Parser.mly"
                           ( { Ast.identifier = _1; Ast.array_dims = []; } )
# 963 "Parser.ml"
               : 'declarator))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : string) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'array_size) in
    Obj.repr(
# 398 "Parser.mly"
                           ( { Ast.identifier = _1; Ast.array_dims = _2; } )
# 971 "Parser.ml"
               : 'declarator))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'attr_block) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'all_type) in
    Obj.repr(
# 407 "Parser.mly"
                                (
    let attr = get_ptr_attr _1 in
    (*check the type is build in type or used defined type.*)
    let rec is_foreign s =
      match s with
        Ast.Ptr(a) -> is_foreign a
      | Ast.Foreign _ -> true
      | _ -> false
    in
    let is_bare_foreign s =
      match s with
      | Ast.Foreign _ -> true
      | _ -> false
    in
    (*'isptr', 'isary', only allowed for bare user defined type.*)
    (*'readonly' only allowed for user defined type.*)
    if attr.Ast.pa_isptr && not (is_bare_foreign _2) then
      failwithf "'isptr', attributes are only for user defined type, not for `%s'." (Ast.get_tystr _2)
    else if attr.Ast.pa_isary && not (is_bare_foreign _2) then
      failwithf "'isary', attributes are only for user defined type, not for `%s'." (Ast.get_tystr _2)
    else if attr.Ast.pa_rdonly && not (is_foreign _2) then
      failwithf "'readonly', attributes are only for user defined type, not for `%s'." (Ast.get_tystr _2)
    else if attr.Ast.pa_rdonly && not (attr.Ast.pa_isptr) then
      failwithf "'readonly' attribute is only used with 'isptr' attribute."    else
    match _2 with
      Ast.Ptr _ -> fun x -> Ast.PTPtr(_2, get_ptr_attr _1)
    | _         ->
      if _1 <> [] then
        let attr = get_ptr_attr _1 in
        match _2 with
          Ast.Foreign s ->
            if attr.Ast.pa_isptr || attr.Ast.pa_isary then fun x -> Ast.PTPtr(_2, attr)
            else
              (* thinking about 'user_defined_type var[4]' *)
              fun is_ary ->
                if is_ary then Ast.PTPtr(_2, attr)
                else failwithf "`%s' is considered plain type but decorated with pointer attributes" s
        | _ ->
          fun is_ary ->
            if is_ary then Ast.PTPtr(_2, attr)
            else failwithf "unexpected pointer attributes for `%s'" (Ast.get_tystr _2)
      else
        fun is_ary ->
          if is_ary then Ast.PTPtr(_2, get_ptr_attr [])
          else  Ast.PTVal _2
    )
# 1024 "Parser.ml"
               : 'param_type))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'all_type) in
    Obj.repr(
# 453 "Parser.mly"
             (
    match _1 with
      Ast.Ptr _ -> fun x -> Ast.PTPtr(_1, get_ptr_attr [])
    | _         ->
      fun is_ary ->
        if is_ary then Ast.PTPtr(_1, get_ptr_attr [])
        else  Ast.PTVal _1
    )
# 1038 "Parser.ml"
               : 'param_type))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 3 : 'attr_block) in
    let _3 = (Parsing.peek_val __caml_parser_env 1 : 'type_spec) in
    let _4 = (Parsing.peek_val __caml_parser_env 0 : 'pointer) in
    Obj.repr(
# 461 "Parser.mly"
                                        (
      let attr = get_ptr_attr _1
      in fun x -> Ast.PTPtr(_4 _3, { attr with Ast.pa_rdonly = true })
    )
# 1050 "Parser.ml"
               : 'param_type))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'type_spec) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : 'pointer) in
    Obj.repr(
# 465 "Parser.mly"
                             (
      let attr = get_ptr_attr []
      in fun x -> Ast.PTPtr(_3 _2, { attr with Ast.pa_rdonly = true })
    )
# 1061 "Parser.ml"
               : 'param_type))
; (fun __caml_parser_env ->
    Obj.repr(
# 472 "Parser.mly"
                                  ( failwith "no attribute specified." )
# 1067 "Parser.ml"
               : 'attr_block))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'key_val_pairs) in
    Obj.repr(
# 473 "Parser.mly"
                                  ( _2 )
# 1074 "Parser.ml"
               : 'attr_block))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'key_val_pair) in
    Obj.repr(
# 476 "Parser.mly"
                                      ( [_1] )
# 1081 "Parser.ml"
               : 'key_val_pairs))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'key_val_pairs) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : 'key_val_pair) in
    Obj.repr(
# 477 "Parser.mly"
                                      (  _3 :: _1 )
# 1089 "Parser.ml"
               : 'key_val_pairs))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : string) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 480 "Parser.mly"
                                             ( (_1, Ast.AString(_3)) )
# 1097 "Parser.ml"
               : 'key_val_pair))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : string) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : int) in
    Obj.repr(
# 481 "Parser.mly"
                                             ( (_1, Ast.ANumber(_3)) )
# 1105 "Parser.ml"
               : 'key_val_pair))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 482 "Parser.mly"
                                             ( (_1, Ast.AString("")) )
# 1112 "Parser.ml"
               : 'key_val_pair))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 485 "Parser.mly"
                                      ( Ast.Struct(_2) )
# 1119 "Parser.ml"
               : 'struct_specifier))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 486 "Parser.mly"
                                      ( Ast.Union(_2) )
# 1126 "Parser.ml"
               : 'union_specifier))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 487 "Parser.mly"
                                      ( Ast.Enum(_2) )
# 1133 "Parser.ml"
               : 'enum_specifier))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 3 : 'struct_specifier) in
    let _3 = (Parsing.peek_val __caml_parser_env 1 : 'member_list) in
    Obj.repr(
# 489 "Parser.mly"
                                                                (
    let s = { Ast.sname = (match _1 with Ast.Struct s -> s | _ -> "");
              Ast.mlist = List.rev _3; }
    in Ast.StructDef(s)
  )
# 1145 "Parser.ml"
               : 'struct_definition))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 3 : 'union_specifier) in
    let _3 = (Parsing.peek_val __caml_parser_env 1 : 'member_list) in
    Obj.repr(
# 495 "Parser.mly"
                                                              (
    let s = { Ast.sname = (match _1 with Ast.Union s -> s | _ -> "");
              Ast.mlist = List.rev _3; }
    in Ast.UnionDef(s)
  )
# 1157 "Parser.ml"
               : 'union_definition))
; (fun __caml_parser_env ->
    let _3 = (Parsing.peek_val __caml_parser_env 1 : 'enum_body) in
    Obj.repr(
# 502 "Parser.mly"
                                                 (
      let e = { Ast.enname = ""; Ast.enbody = _3; }
      in Ast.EnumDef(e)
    )
# 1167 "Parser.ml"
               : 'enum_definition))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 3 : 'enum_specifier) in
    let _3 = (Parsing.peek_val __caml_parser_env 1 : 'enum_body) in
    Obj.repr(
# 506 "Parser.mly"
                                             (
      let e = { Ast.enname = (match _1 with Ast.Enum s -> s | _ -> "");
                Ast.enbody = _3; }
      in Ast.EnumDef(e)
    )
# 1179 "Parser.ml"
               : 'enum_definition))
; (fun __caml_parser_env ->
    Obj.repr(
# 513 "Parser.mly"
                       ( [] )
# 1185 "Parser.ml"
               : 'enum_body))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'enum_eles) in
    Obj.repr(
# 514 "Parser.mly"
                       ( List.rev _1 )
# 1192 "Parser.ml"
               : 'enum_body))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'enum_ele) in
    Obj.repr(
# 517 "Parser.mly"
                              ( [_1] )
# 1199 "Parser.ml"
               : 'enum_eles))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'enum_eles) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : 'enum_ele) in
    Obj.repr(
# 518 "Parser.mly"
                              ( _3 :: _1 )
# 1207 "Parser.ml"
               : 'enum_eles))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 521 "Parser.mly"
                                   ( (_1, Ast.EnumValNone) )
# 1214 "Parser.ml"
               : 'enum_ele))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : string) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 522 "Parser.mly"
                                   ( (_1, Ast.EnumVal (Ast.AString _3)) )
# 1222 "Parser.ml"
               : 'enum_ele))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : string) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : int) in
    Obj.repr(
# 523 "Parser.mly"
                                   ( (_1, Ast.EnumVal (Ast.ANumber _3)) )
# 1230 "Parser.ml"
               : 'enum_ele))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'struct_definition) in
    Obj.repr(
# 526 "Parser.mly"
                                      ( _1 )
# 1237 "Parser.ml"
               : 'composite_defs))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'union_definition) in
    Obj.repr(
# 527 "Parser.mly"
                                      ( _1 )
# 1244 "Parser.ml"
               : 'composite_defs))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'enum_definition) in
    Obj.repr(
# 528 "Parser.mly"
                                      ( _1 )
# 1251 "Parser.ml"
               : 'composite_defs))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'member_def) in
    Obj.repr(
# 531 "Parser.mly"
                                      ( [_1] )
# 1258 "Parser.ml"
               : 'member_list))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'member_list) in
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'member_def) in
    Obj.repr(
# 532 "Parser.mly"
                                      ( _2 :: _1 )
# 1266 "Parser.ml"
               : 'member_list))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'all_type) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'declarator) in
    Obj.repr(
# 535 "Parser.mly"
                                ( (_1, _2) )
# 1274 "Parser.ml"
               : 'member_def))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 540 "Parser.mly"
                                  ( [_1] )
# 1281 "Parser.ml"
               : 'func_list))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'func_list) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 541 "Parser.mly"
                                  ( _3 :: _1 )
# 1289 "Parser.ml"
               : 'func_list))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 544 "Parser.mly"
                                  ( _1 )
# 1296 "Parser.ml"
               : 'module_path))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 2 : 'module_path) in
    let _4 = (Parsing.peek_val __caml_parser_env 0 : 'func_list) in
    Obj.repr(
# 546 "Parser.mly"
                                                         (
      { Ast.mname = _2; Ast.flist = List.rev _4; }
    )
# 1306 "Parser.ml"
               : 'import_declaration))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 2 : 'module_path) in
    Obj.repr(
# 549 "Parser.mly"
                                   (
      { Ast.mname = _2; Ast.flist = ["*"]; }
    )
# 1315 "Parser.ml"
               : 'import_declaration))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 0 : string) in
    Obj.repr(
# 554 "Parser.mly"
                                      ( _2 )
# 1322 "Parser.ml"
               : 'include_declaration))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'include_declaration) in
    Obj.repr(
# 556 "Parser.mly"
                                             ( [_1] )
# 1329 "Parser.ml"
               : 'include_declarations))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'include_declarations) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'include_declaration) in
    Obj.repr(
# 557 "Parser.mly"
                                             ( _2 :: _1 )
# 1337 "Parser.ml"
               : 'include_declarations))
; (fun __caml_parser_env ->
    let _3 = (Parsing.peek_val __caml_parser_env 2 : 'trusted_block) in
    Obj.repr(
# 563 "Parser.mly"
                                                                     (
      List.rev _3
    )
# 1346 "Parser.ml"
               : 'enclave_functions))
; (fun __caml_parser_env ->
    let _3 = (Parsing.peek_val __caml_parser_env 2 : 'untrusted_block) in
    Obj.repr(
# 566 "Parser.mly"
                                                          (
      List.rev _3
    )
# 1355 "Parser.ml"
               : 'enclave_functions))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'trusted_functions) in
    Obj.repr(
# 571 "Parser.mly"
                                             ( _1 )
# 1362 "Parser.ml"
               : 'trusted_block))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'include_declarations) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'trusted_functions) in
    Obj.repr(
# 572 "Parser.mly"
                                             (
      trusted_headers := !trusted_headers @ List.rev _1; _2
    )
# 1372 "Parser.ml"
               : 'trusted_block))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'untrusted_functions) in
    Obj.repr(
# 577 "Parser.mly"
                                             ( _1 )
# 1379 "Parser.ml"
               : 'untrusted_block))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'include_declarations) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'untrusted_functions) in
    Obj.repr(
# 578 "Parser.mly"
                                             (
      untrusted_headers := !untrusted_headers @ List.rev _1; _2
    )
# 1389 "Parser.ml"
               : 'untrusted_block))
; (fun __caml_parser_env ->
    Obj.repr(
# 584 "Parser.mly"
                               ( true )
# 1395 "Parser.ml"
               : 'access_modifier))
; (fun __caml_parser_env ->
    Obj.repr(
# 585 "Parser.mly"
                               ( false  )
# 1401 "Parser.ml"
               : 'access_modifier))
; (fun __caml_parser_env ->
    Obj.repr(
# 588 "Parser.mly"
                                          ( [] )
# 1407 "Parser.ml"
               : 'trusted_functions))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 3 : 'trusted_functions) in
    let _2 = (Parsing.peek_val __caml_parser_env 2 : 'access_modifier) in
    let _3 = (Parsing.peek_val __caml_parser_env 1 : 'func_def) in
    Obj.repr(
# 589 "Parser.mly"
                                                          (
      check_ptr_attr _3 (symbol_start_pos(), symbol_end_pos());
      Ast.Trusted { Ast.tf_fdecl = _3; Ast.tf_is_priv = _2 } :: _1
    )
# 1419 "Parser.ml"
               : 'trusted_functions))
; (fun __caml_parser_env ->
    Obj.repr(
# 595 "Parser.mly"
                                                      ( [] )
# 1425 "Parser.ml"
               : 'untrusted_functions))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'untrusted_functions) in
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'untrusted_func_def) in
    Obj.repr(
# 596 "Parser.mly"
                                                      ( _2 :: _1 )
# 1433 "Parser.ml"
               : 'untrusted_functions))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'all_type) in
    let _2 = (Parsing.peek_val __caml_parser_env 1 : string) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : 'parameter_list) in
    Obj.repr(
# 599 "Parser.mly"
                                              (
      { Ast.fname = _2; Ast.rtype = _1; Ast.plist = List.rev _3 ; }
    )
# 1444 "Parser.ml"
               : 'func_def))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 3 : 'all_type) in
    let _2 = (Parsing.peek_val __caml_parser_env 2 : 'array_size) in
    let _3 = (Parsing.peek_val __caml_parser_env 1 : string) in
    let _4 = (Parsing.peek_val __caml_parser_env 0 : 'parameter_list) in
    Obj.repr(
# 602 "Parser.mly"
                                                   (
      failwithf "%s: returning an array is not supported - use pointer instead." _3
    )
# 1456 "Parser.ml"
               : 'func_def))
; (fun __caml_parser_env ->
    Obj.repr(
# 607 "Parser.mly"
                                   ( [] )
# 1462 "Parser.ml"
               : 'parameter_list))
; (fun __caml_parser_env ->
    Obj.repr(
# 608 "Parser.mly"
                                   ( [] )
# 1468 "Parser.ml"
               : 'parameter_list))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'parameter_defs) in
    Obj.repr(
# 609 "Parser.mly"
                                   ( _2 )
# 1475 "Parser.ml"
               : 'parameter_list))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'parameter_def) in
    Obj.repr(
# 612 "Parser.mly"
                                        ( [_1] )
# 1482 "Parser.ml"
               : 'parameter_defs))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'parameter_defs) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : 'parameter_def) in
    Obj.repr(
# 613 "Parser.mly"
                                        ( _3 :: _1 )
# 1490 "Parser.ml"
               : 'parameter_defs))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'param_type) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'declarator) in
    Obj.repr(
# 616 "Parser.mly"
                                     (
    let pt = _1 (Ast.is_array _2) in
    let is_void =
      match pt with
          Ast.PTVal v -> v = Ast.Void
        | _           -> false
    in
      if is_void then
        failwithf "parameter `%s' has `void' type." _2.Ast.identifier
      else
        (pt, _2)
  )
# 1509 "Parser.ml"
               : 'parameter_def))
; (fun __caml_parser_env ->
    Obj.repr(
# 630 "Parser.mly"
                               ( false )
# 1515 "Parser.ml"
               : 'propagate_errno))
; (fun __caml_parser_env ->
    Obj.repr(
# 631 "Parser.mly"
                               ( true  )
# 1521 "Parser.ml"
               : 'propagate_errno))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 3 : 'attr_block) in
    let _2 = (Parsing.peek_val __caml_parser_env 2 : 'func_def) in
    let _3 = (Parsing.peek_val __caml_parser_env 1 : 'allow_list) in
    let _4 = (Parsing.peek_val __caml_parser_env 0 : 'propagate_errno) in
    Obj.repr(
# 634 "Parser.mly"
                                                                   (
      check_ptr_attr _2 (symbol_start_pos(), symbol_end_pos());
      let fattr = get_func_attr _1 in
      Ast.Untrusted { Ast.uf_fdecl = _2; Ast.uf_fattr = fattr; Ast.uf_allow_list = _3; Ast.uf_propagate_errno = _4 }
    )
# 1535 "Parser.ml"
               : 'untrusted_func_def))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'func_def) in
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'allow_list) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : 'propagate_errno) in
    Obj.repr(
# 639 "Parser.mly"
                                        (
      check_ptr_attr _1 (symbol_start_pos(), symbol_end_pos());
      let fattr = get_func_attr [] in
      Ast.Untrusted { Ast.uf_fdecl = _1; Ast.uf_fattr = fattr; Ast.uf_allow_list = _2; Ast.uf_propagate_errno = _3 }
    )
# 1548 "Parser.ml"
               : 'untrusted_func_def))
; (fun __caml_parser_env ->
    Obj.repr(
# 646 "Parser.mly"
                                     ( [] )
# 1554 "Parser.ml"
               : 'allow_list))
; (fun __caml_parser_env ->
    Obj.repr(
# 647 "Parser.mly"
                                     ( [] )
# 1560 "Parser.ml"
               : 'allow_list))
; (fun __caml_parser_env ->
    let _3 = (Parsing.peek_val __caml_parser_env 1 : 'func_list) in
    Obj.repr(
# 648 "Parser.mly"
                                     ( _3 )
# 1567 "Parser.ml"
               : 'allow_list))
; (fun __caml_parser_env ->
    Obj.repr(
# 654 "Parser.mly"
                           ( [] )
# 1573 "Parser.ml"
               : 'expressions))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'expressions) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'include_declaration) in
    Obj.repr(
# 655 "Parser.mly"
                                              ( Ast.Include(_2)   :: _1 )
# 1581 "Parser.ml"
               : 'expressions))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'expressions) in
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'import_declaration) in
    Obj.repr(
# 656 "Parser.mly"
                                              ( Ast.Importing(_2) :: _1 )
# 1589 "Parser.ml"
               : 'expressions))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'expressions) in
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'composite_defs) in
    Obj.repr(
# 657 "Parser.mly"
                                              ( Ast.Composite(_2) :: _1 )
# 1597 "Parser.ml"
               : 'expressions))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'expressions) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'enclave_functions) in
    Obj.repr(
# 658 "Parser.mly"
                                              ( Ast.Interface(_2) :: _1 )
# 1605 "Parser.ml"
               : 'expressions))
; (fun __caml_parser_env ->
    let _3 = (Parsing.peek_val __caml_parser_env 1 : 'expressions) in
    Obj.repr(
# 661 "Parser.mly"
                                                  (
      { Ast.ename = "";
        Ast.eexpr = List.rev _3 }
    )
# 1615 "Parser.ml"
               : 'enclave_def))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'enclave_def) in
    Obj.repr(
# 670 "Parser.mly"
                                          ( _1 )
# 1622 "Parser.ml"
               : Ast.enclave))
(* Entry start_parsing *)
; (fun __caml_parser_env -> raise (Parsing.YYexit (Parsing.peek_val __caml_parser_env 0)))
|]
let yytables =
  { Parsing.actions=yyact;
    Parsing.transl_const=yytransl_const;
    Parsing.transl_block=yytransl_block;
    Parsing.lhs=yylhs;
    Parsing.len=yylen;
    Parsing.defred=yydefred;
    Parsing.dgoto=yydgoto;
    Parsing.sindex=yysindex;
    Parsing.rindex=yyrindex;
    Parsing.gindex=yygindex;
    Parsing.tablesize=yytablesize;
    Parsing.table=yytable;
    Parsing.check=yycheck;
    Parsing.error_function=parse_error;
    Parsing.names_const=yynames_const;
    Parsing.names_block=yynames_block }
let start_parsing (lexfun : Lexing.lexbuf -> token) (lexbuf : Lexing.lexbuf) =
   (Parsing.yyparse yytables 1 lexfun lexbuf : Ast.enclave)
;;
