; This file is a part of Julia. License is MIT: https://julialang.org/license

; RUN: opt -enable-new-pm=0 -load libjulia-codegen%shlibext -FinalLowerGC -S %s | FileCheck %s
; RUN: opt -enable-new-pm=1 --load-pass-plugin=libjulia-codegen%shlibext -passes='FinalLowerGC' -S %s | FileCheck %s


@tag = external addrspace(10) global {}

declare void @boxed_simple({} addrspace(10)*, {} addrspace(10)*)
declare {} addrspace(10)* @ijl_box_int64(i64)
declare {}*** @julia.ptls_states()
declare {}*** @julia.get_pgcstack()

declare noalias nonnull {} addrspace(10)** @julia.new_gc_frame(i32)
declare void @julia.push_gc_frame({} addrspace(10)**, i32)
declare {} addrspace(10)** @julia.get_gc_frame_slot({} addrspace(10)**, i32)
declare void @julia.pop_gc_frame({} addrspace(10)**)
declare noalias nonnull {} addrspace(10)* @julia.gc_alloc_bytes(i8*, i64) #0

attributes #0 = { allocsize(1) }

define void @gc_frame_lowering(i64 %a, i64 %b) {
top:
; CHECK-LABEL: @gc_frame_lowering
; CHECK: %gcframe = alloca {} addrspace(10)*, i32 4
  %gcframe = call {} addrspace(10)** @julia.new_gc_frame(i32 2)
; CHECK:  [[GCFRAME_SLOT:%.*]] = call {}*** @julia.get_pgcstack()
  %pgcstack = call {}*** @julia.get_pgcstack()
; CHECK-DAG: [[GCFRAME_SIZE_PTR:%.*]] = getelementptr inbounds {} addrspace(10)*, {} addrspace(10)** %gcframe, i32 0
; CHECK-DAG: [[GCFRAME_SIZE_PTR2:%.*]] = bitcast {} addrspace(10)** [[GCFRAME_SIZE_PTR]] to i64*
; CHECK-DAG: store i64 8, i64* [[GCFRAME_SIZE_PTR2]], align 8, !tbaa !0
; CHECK-DAG: [[PREV_GCFRAME_PTR:%.*]] = getelementptr inbounds {} addrspace(10)*, {} addrspace(10)** %gcframe, i32 1
; CHECK-DAG: [[PREV_GCFRAME_PTR2:%.*]] = bitcast {} addrspace(10)** [[PREV_GCFRAME_PTR]] to {}***
; CHECK-DAG: [[PREV_GCFRAME:%.*]] = load {}**, {}*** [[GCFRAME_SLOT]], align 8
; CHECK-DAG: store {}** [[PREV_GCFRAME]], {}*** [[PREV_GCFRAME_PTR2]], align 8, !tbaa !0
; CHECK-DAG: [[GCFRAME_SLOT2:%.*]] = bitcast {}*** [[GCFRAME_SLOT]] to {} addrspace(10)***
; CHECK-NEXT: store {} addrspace(10)** %gcframe, {} addrspace(10)*** [[GCFRAME_SLOT2]], align 8
  call void @julia.push_gc_frame({} addrspace(10)** %gcframe, i32 2)
  %aboxed = call {} addrspace(10)* @ijl_box_int64(i64 signext %a)
; CHECK: %frame_slot_1 = getelementptr inbounds {} addrspace(10)*, {} addrspace(10)** %gcframe, i32 3
  %frame_slot_1 = call {} addrspace(10)** @julia.get_gc_frame_slot({} addrspace(10)** %gcframe, i32 1)
  store {} addrspace(10)* %aboxed, {} addrspace(10)** %frame_slot_1, align 8
  %bboxed = call {} addrspace(10)* @ijl_box_int64(i64 signext %b)
; CHECK: %frame_slot_2 = getelementptr inbounds {} addrspace(10)*, {} addrspace(10)** %gcframe, i32 2
  %frame_slot_2 = call {} addrspace(10)** @julia.get_gc_frame_slot({} addrspace(10)** %gcframe, i32 0)
  store {} addrspace(10)* %bboxed, {} addrspace(10)** %frame_slot_2, align 8
; CHECK: call void @boxed_simple({} addrspace(10)* %aboxed, {} addrspace(10)* %bboxed)
  call void @boxed_simple({} addrspace(10)* %aboxed, {} addrspace(10)* %bboxed)
; CHECK-NEXT: [[PREV_GCFRAME_PTR3:%.*]] = getelementptr inbounds {} addrspace(10)*, {} addrspace(10)** %gcframe, i32 1
; CHECK-NEXT: [[PREV_GCFRAME_PTR4:%.*]] = load {} addrspace(10)*, {} addrspace(10)** [[PREV_GCFRAME_PTR3]], align 8, !tbaa !0
; CHECK-NEXT: [[GCFRAME_SLOT4:%.*]] = bitcast {}*** [[GCFRAME_SLOT]] to {} addrspace(10)**
; CHECK-NEXT: store {} addrspace(10)* [[PREV_GCFRAME_PTR4]], {} addrspace(10)** [[GCFRAME_SLOT4]], align 8, !tbaa !0
  call void @julia.pop_gc_frame({} addrspace(10)** %gcframe)
; CHECK-NEXT: ret void
  ret void
}

define {} addrspace(10)* @gc_alloc_lowering() {
top:
; CHECK-LABEL: @gc_alloc_lowering
  %pgcstack = call {}*** @julia.get_pgcstack()
  %ptls = call {}*** @julia.ptls_states()
  %ptls_i8 = bitcast {}*** %ptls to i8*
; CHECK: %v = call noalias nonnull dereferenceable({{[0-9]+}}) {} addrspace(10)* @ijl_gc_pool_alloc
  %v = call {} addrspace(10)* @julia.gc_alloc_bytes(i8* %ptls_i8, i64 8)
  %0 = bitcast {} addrspace(10)* %v to {} addrspace(10)* addrspace(10)*
  %1 = getelementptr {} addrspace(10)*, {} addrspace(10)* addrspace(10)* %0, i64 -1
  store {} addrspace(10)* @tag, {} addrspace(10)* addrspace(10)* %1, align 8, !tbaa !0
  ret {} addrspace(10)* %v
}

define {} addrspace(10)* @gc_alloc_lowering_var(i64 %size) {
top:
; CHECK-LABEL: @gc_alloc_lowering_var
  %pgcstack = call {}*** @julia.get_pgcstack()
  %ptls = call {}*** @julia.ptls_states()
  %ptls_i8 = bitcast {}*** %ptls to i8*
; CHECK: %0 = add i64 %size, 8
; CHECK: %v = call noalias nonnull dereferenceable(8) {} addrspace(10)* @ijl_gc_alloc_typed(i8* %ptls_i8, i64 %0, i8* null)
  %v = call {} addrspace(10)* @julia.gc_alloc_bytes(i8* %ptls_i8, i64 %size)
  %0 = bitcast {} addrspace(10)* %v to {} addrspace(10)* addrspace(10)*
  %1 = getelementptr {} addrspace(10)*, {} addrspace(10)* addrspace(10)* %0, i64 -1
  store {} addrspace(10)* @tag, {} addrspace(10)* addrspace(10)* %1, align 8, !tbaa !0
  ret {} addrspace(10)* %v
}

!0 = !{!1, !1, i64 0}
!1 = !{!"jtbaa_gcframe", !2, i64 0}
!2 = !{!"jtbaa"}
