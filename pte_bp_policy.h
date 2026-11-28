/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DFM_PTE_BP_POLICY_H
#define DFM_PTE_BP_POLICY_H
/* Shared with the host fault model; these are the production predicates. */
static inline int dfm_pte_validate(const struct dfm_pte_set_req *r,
                                   uint64_t limit)
{
    unsigned int i, j;
    if (r->abi_version != DFM_PTE_ABI_VERSION || r->pid <= 0 || r->flags ||
        r->reserved[0] || r->reserved[1] || !r->point_count ||
        r->point_count > DFM_PTE_MAX_POINTS)
        return -EINVAL;
    for (i = 0; i < DFM_PTE_MAX_POINTS; ++i) {
        uint64_t a = r->addresses[i];
        if (i >= r->point_count) {
            if (a) return -EINVAL;
            continue;
        }
        if (!a || (a & 3) || a >= limit || limit - a < 4) return -EINVAL;
        for (j = 0; j < i; ++j)
            if (a == r->addresses[j]) return -EEXIST;
    }
    return 0;
}

static inline int dfm_pte_value_matches(uint64_t now, uint64_t original,
                                      uint64_t uxn, uint64_t mutable, int armed)
{
    return !((now ^ (original | (armed ? uxn : 0))) & ~mutable);
}

/* Native exception boundaries can destroy an exclusive reservation. Refuse
 * the whole exclusive/CAS/LSE classes instead of risking an endless retry. */
static inline int dfm_pte_instruction_safe(uint32_t insn)
{
    return (insn & 0x3f000000U) != 0x08000000U &&
           (insn & 0x3b200c00U) != 0x38200000U;
}
static inline int dfm_pte_rule_uses_fp(const struct dfm_pte_rule *r)
{
    return r->q_mask || (r->flags & (DFM_PTE_RULE_FPCR | DFM_PTE_RULE_FPSR));
}
static inline int dfm_pte_rule_matches(const struct dfm_pte_rule *r, uint64_t x0)
{
    return !(r->flags & DFM_PTE_RULE_MATCH_X0) || r->x[0] == x0;
}
static inline int dfm_pte_probability_pass(const struct dfm_pte_rule *r, uint32_t random)
{
    return !(r->flags & DFM_PTE_RULE_PROBABILITY) ||
           (((uint64_t)random * 100U) >> 32) < r->reserved;
}
static inline int dfm_pte_validate_rules(const struct dfm_pte_rules_req *req,
                                        const struct dfm_pte_rule *rules,
                                        const uint64_t *points, unsigned int count,
                                        uint64_t limit, int can_write_fp)
{
    unsigned int i, j;
    if (req->abi_version != DFM_PTE_RULES_ABI_VERSION || req->flags ||
        req->reserved || !req->generation || req->count > DFM_PTE_MAX_POINTS ||
        (!!req->count != !!req->rules)) return -EINVAL;
    for (i = 0; i < req->count; ++i) {
        const struct dfm_pte_rule *r = &rules[i];
        if (!r->address || (r->address & 3) || r->address >= limit || limit-r->address < 4 ||
            (r->x_mask & (1U << 31)) ||
            ((r->flags & DFM_PTE_RULE_PROBABILITY) ? r->reserved > 100 : r->reserved != 0) ||
            (r->flags & ~(DFM_PTE_RULE_FPCR | DFM_PTE_RULE_FPSR | DFM_PTE_RULE_MATCH_X0 | DFM_PTE_RULE_PROBABILITY)) ||
            !(r->x_mask || r->q_mask || (r->flags & (DFM_PTE_RULE_FPCR | DFM_PTE_RULE_FPSR)))) return -EINVAL;
        if ((r->flags & DFM_PTE_RULE_MATCH_X0) &&
            ((r->x_mask & 1U) || !r->x[0])) return -EINVAL;
        for (j = 0; j < i; ++j)
            if (rules[j].address == r->address) return -EEXIST;
        for (j = 0; j < count; ++j) if (points[j] == r->address) break;
        if (j == count) return -ENOENT;
        for (j = 0; j < 31; ++j)
            if (!(r->x_mask & (1U << j)) && r->x[j] &&
                !(j == 0 && (r->flags & DFM_PTE_RULE_MATCH_X0))) return -EINVAL;
        for (j = 0; j < 32; ++j)
            if (!(r->q_mask & (1U << j)) && (r->q[j][0] || r->q[j][1])) return -EINVAL;
        if (!(r->flags & DFM_PTE_RULE_FPCR) && r->fpcr) return -EINVAL;
        if (!(r->flags & DFM_PTE_RULE_FPSR) && r->fpsr) return -EINVAL;
        if (dfm_pte_rule_uses_fp(r) && !can_write_fp) return -EOPNOTSUPP;
    }
    return 0;
}
#endif
