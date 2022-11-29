#pragma once

namespace ir {
    class Function;
}

class namespacet;
class goto_programt;

bool
convert_to_cbmc(ir::Function* func, goto_programt& program, const namespacet& ns);
