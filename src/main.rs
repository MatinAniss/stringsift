use boa_engine::{
    ast::{
        expression::literal::Literal, Declaration, Expression, Statement, StatementList,
        StatementListItem,
    },
    interner::Sym,
    Context, Source,
};
use clap::Parser;
use reqwest_spooftls::{Client, Fingerprint};
use scraper::{Html, Selector};
use tokio::fs;
use url::Url;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// The supplied URL that will be sifted
    #[arg(short, long)]
    url: Url,

    /// Spoof TLS to behave like a browser
    #[arg(short, long)]
    spoof: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let http_client = {
        let client = Client::builder();
        if args.spoof {
            client.use_fingerprint(Fingerprint::Chrome131)
        } else {
            client
        }
    }
    .build()
    .unwrap();

    let res = http_client
        .get(args.url.as_str())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let parsed_html = Html::parse_document(&res);

    let js_urls = parsed_html
        .root_element()
        .select(&Selector::parse("script").unwrap())
        .filter_map(|e| e.attr("src").map(|src| args.url.clone().join(src).unwrap()))
        .collect::<Vec<_>>();

    let _ = fs::create_dir(format!("./{}", args.url.domain().unwrap())).await;

    for url in js_urls {
        let result = sift_url(&http_client, &url).await;

        if !result.is_empty() {
            let _ = fs::write(
                format!(
                    "./{}/{}.txt",
                    args.url.domain().unwrap(),
                    url.path_segments().unwrap().last().unwrap()
                ),
                result.join("\n"),
            )
            .await;
        }
    }
}

async fn sift_url(http_client: &Client, url: &Url) -> Vec<String> {
    let res = http_client
        .get(url.as_str())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let mut parser = boa_parser::Parser::new(Source::from_bytes(&res));
    let mut ctx = Context::default();
    let script = parser.parse_eval(true, ctx.interner_mut()).unwrap();

    extract_strings_from_statements_list(script.statements())
        .iter()
        .filter_map(|s| {
            let string = ctx.interner().resolve(*s).unwrap().to_string();
            if string.is_empty() {
                None
            } else {
                Some(string.replace('\n', ""))
            }
        })
        .collect::<Vec<_>>()
}

fn extract_strings_from_statements_list(statements: &StatementList) -> Vec<Sym> {
    let mut symbols = Vec::new();

    fn match_expression(expression: &Expression) -> Vec<Sym> {
        let mut symbols = Vec::new();

        match expression {
            Expression::This => {}
            Expression::Identifier(_identifier) => {}
            Expression::Literal(literal) => match literal {
                Literal::String(string) => {
                    symbols.push(string.clone());
                }
                _ => {}
            },
            Expression::RegExpLiteral(_reg_exp_literal) => {}
            Expression::ArrayLiteral(_array_literal) => {}
            Expression::ObjectLiteral(_object_literal) => {}
            Expression::Spread(spread) => {
                symbols.append(&mut match_expression(spread.target()));
            }
            Expression::FunctionExpression(function_expression) => {
                symbols.append(&mut extract_strings_from_statements_list(
                    function_expression.body().statement_list(),
                ));
            }
            Expression::ArrowFunction(arrow_function) => {
                symbols.append(&mut extract_strings_from_statements_list(
                    arrow_function.body().statement_list(),
                ));
            }
            Expression::AsyncArrowFunction(async_arrow_function) => {
                symbols.append(&mut extract_strings_from_statements_list(
                    async_arrow_function.body().statement_list(),
                ));
            }
            Expression::GeneratorExpression(generator_expression) => {
                symbols.append(&mut extract_strings_from_statements_list(
                    generator_expression.body().statement_list(),
                ));
            }
            Expression::AsyncFunctionExpression(async_function_expression) => {
                symbols.append(&mut extract_strings_from_statements_list(
                    async_function_expression.body().statement_list(),
                ));
            }
            Expression::AsyncGeneratorExpression(async_generator_expression) => {
                symbols.append(&mut extract_strings_from_statements_list(
                    async_generator_expression.body().statement_list(),
                ));
            }
            Expression::ClassExpression(_class_expression) => {}
            Expression::TemplateLiteral(_template_literal) => {}
            Expression::PropertyAccess(_property_access) => {}
            Expression::New(new) => {
                symbols.append(&mut match_expression(new.constructor()));
                for argument in new.arguments() {
                    symbols.append(&mut match_expression(argument));
                }
            }
            Expression::Call(call) => {
                symbols.append(&mut match_expression(call.function()));
            }
            Expression::SuperCall(super_call) => {
                for argument in super_call.arguments() {
                    symbols.append(&mut match_expression(argument));
                }
            }
            Expression::ImportCall(import_call) => {
                symbols.append(&mut match_expression(import_call.argument()));
            }
            Expression::Optional(optional) => {
                symbols.append(&mut match_expression(optional.target()));
            }
            Expression::TaggedTemplate(tagged_template) => {
                symbols.append(&mut match_expression(tagged_template.tag()));
                for expr in tagged_template.exprs() {
                    symbols.append(&mut match_expression(expr));
                }
            }
            Expression::NewTarget => {}
            Expression::ImportMeta => {}
            Expression::Assign(assign) => {
                symbols.append(&mut match_expression(assign.rhs()));
            }
            Expression::Unary(unary) => {
                symbols.append(&mut match_expression(unary.target()));
            }
            Expression::Update(_update) => {}
            Expression::Binary(binary) => {
                symbols.append(&mut match_expression(binary.rhs()));
                symbols.append(&mut match_expression(binary.lhs()));
            }
            Expression::BinaryInPrivate(binary_in_private) => {
                symbols.append(&mut match_expression(binary_in_private.rhs()));
            }
            Expression::Conditional(conditional) => {
                symbols.append(&mut match_expression(conditional.condition()));
                symbols.append(&mut match_expression(conditional.if_false()));
                symbols.append(&mut match_expression(conditional.if_true()));
            }
            Expression::Await(await_expression) => {
                symbols.append(&mut match_expression(await_expression.target()));
            }
            Expression::Yield(yield_expression) => {
                if let Some(target) = yield_expression.target() {
                    symbols.append(&mut match_expression(target));
                }
            }
            Expression::Parenthesized(parenthesized) => {
                symbols.append(&mut match_expression(parenthesized.expression()));
            }
            _ => {}
        }

        symbols
    }

    fn match_statement(statement: &Statement) -> Vec<Sym> {
        let mut symbols = Vec::new();

        match statement {
            Statement::Block(block) => {
                symbols.append(&mut extract_strings_from_statements_list(
                    block.statement_list(),
                ));
            }
            Statement::Var(_var) => {}
            Statement::Empty => {}
            Statement::Expression(expression) => {
                symbols.append(&mut match_expression(expression));
            }
            Statement::If(if_statement) => {
                symbols.append(&mut match_expression(if_statement.cond()));
                symbols.append(&mut match_statement(if_statement.body()));
                if let Some(else_node) = if_statement.else_node() {
                    symbols.append(&mut match_statement(else_node));
                }
            }
            Statement::DoWhileLoop(do_while_loop) => {
                symbols.append(&mut match_expression(do_while_loop.cond()));
                symbols.append(&mut match_statement(do_while_loop.body()));
            }
            Statement::WhileLoop(while_loop) => {
                symbols.append(&mut match_expression(while_loop.condition()));
                symbols.append(&mut match_statement(while_loop.body()));
            }
            Statement::ForLoop(for_loop) => {
                symbols.append(&mut match_statement(for_loop.body()));
                if let Some(condition) = for_loop.condition() {
                    symbols.append(&mut match_expression(condition));
                }
                if let Some(final_expr) = for_loop.final_expr() {
                    symbols.append(&mut match_expression(final_expr));
                }
            }
            Statement::ForInLoop(_for_in_loop) => {}
            Statement::ForOfLoop(_for_of_loop) => {}
            Statement::Switch(_switch) => {}
            Statement::Continue(_continue_statement) => {}
            Statement::Break(_break_statement) => {}
            Statement::Return(return_statement) => {
                if let Some(return_statement) = return_statement.target() {
                    symbols.append(&mut match_expression(return_statement));
                }
            }
            Statement::Labelled(_labelled) => {}
            Statement::Throw(_throw_statement) => {}
            Statement::Try(_try_statement) => {}
            Statement::With(_with_statement) => {}
        }

        symbols
    }

    fn match_declaration(declaration: &Declaration) -> Vec<Sym> {
        let mut symbols = Vec::new();

        match declaration {
            Declaration::AsyncFunctionDeclaration(async_function_declaration) => {
                symbols.append(&mut extract_strings_from_statements_list(
                    async_function_declaration.body().statement_list(),
                ));
            }
            Declaration::AsyncGeneratorDeclaration(async_declaration) => {
                symbols.append(&mut extract_strings_from_statements_list(
                    async_declaration.body().statement_list(),
                ));
            }
            Declaration::FunctionDeclaration(function_declaration) => {
                symbols.append(&mut extract_strings_from_statements_list(
                    function_declaration.body().statement_list(),
                ));
            }
            Declaration::GeneratorDeclaration(generator_declaration) => {
                symbols.append(&mut extract_strings_from_statements_list(
                    generator_declaration.body().statement_list(),
                ));
            }
            Declaration::ClassDeclaration(class_declartion) => {
                if let Some(super_ref) = class_declartion.super_ref() {
                    symbols.append(&mut match_expression(super_ref));
                }
            }
            Declaration::Lexical(lexical) => {
                for variable in lexical.variable_list().as_ref() {
                    if let Some(variable) = variable.init() {
                        symbols.append(&mut match_expression(variable));
                    }
                }
            }
        }

        symbols
    }

    for s in statements.iter() {
        symbols.append(&mut match s {
            StatementListItem::Statement(statement) => match_statement(statement),
            StatementListItem::Declaration(declaration) => match_declaration(declaration),
        });
    }

    symbols
}
