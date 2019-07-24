import React, { Component } from 'react';
import { connect } from 'react-redux';
import { withRouter } from 'react-router-dom';
import { addEducation } from '../../actions/profileActions';
import TextFieldGroup from '../common/TextFieldGroup';
import TextAreaFieldGroup from '../common/TextAreaFieldGroup';

class AddEducation extends Component {
    constructor(props){
        super(props);
        this.state = {
            school: '',
            degree: '',
            fieldOfStudy: '',
            from        : '',
            to          :'',
            current: false,
            description: '',
            errors: {}
        }
    }
    componentWillReceiveProps(nextProps){
        if(nextProps.errors)
            this.setState({
                errors: nextProps.errors
            })
    }
    changed = (e) => {
        this.setState({
            [e.target.name]: e.target.value
        })
    }
    checked = (e) => {
        this.setState({
            current: !this.state.current
        })
    }
    submit = (e) => {
        e.preventDefault();
        this.props.addEducation(this.state, this.props.history);
    }
  render() {
    const state = this.state;
    return (
<div className='addeducation'>
    <div className='container'>
        <div className='row'>
            <div className='col-md-12 m-auto'>
            <p className="lead text-center">Add any eduaction you got in past years or now</p>
            <form 
            className='custom-form'
            onSubmit={this.submit}>
                <h2 className="text-center">Add Education</h2>
                <hr/>
                <TextFieldGroup
                errors={state.errors}
                id='school_id'
                name='school'
                label='School | University'
                placeholder='Enter school Or university'
                type='text'
                value={state.school}
                onchange={this.changed}
                />
                <TextFieldGroup
                errors={state.errors}
                id='degree_id'
                name='degree'
                label='Degree'
                placeholder='Enter Degree'
                type='text'
                value={state.degree}
                onchange={this.changed}
                />
                <TextFieldGroup
                errors={state.errors}
                id='fieldOfStudy_id'
                name='fieldOfStudy'
                label='Field Of Study'
                placeholder='Enter Field Of Study'
                type='text'
                value={state.fieldOfStudy}
                onchange={this.changed}
                />
                <TextFieldGroup
                errors={state.errors}
                id='from_id'
                name='from'
                label='Start Date'
                placeholder='Enter Start Date Of Study'
                type='date'
                value={state.from}
                onchange={this.changed}
                />
                <TextFieldGroup
                errors={state.errors}
                id='to_id'
                name='to'
                label='End Date'
                placeholder='Enter End Date Of Study'
                type='date'
                value={state.fieldOfStudy}
                onchange={this.changed}
                disabled={state.current?'disabled':''}
                />
                <div className="form-check col-md-8 mx-auto mb-3">
                <input 
                className="form-check-input" 
                type="checkbox" 
                defaultValue={state.current}
                onChange={this.checked} />
                <label className="form-check-label" htmlFor="defaultCheck1">
                    Until Current
                </label>
                </div>
                <TextAreaFieldGroup
                errors={state.errors}
                id='desc_id'
                name='description'
                placeholder='Enter Description'
                value={state.description}
                />
                <button type='submit' className='btn btn-success btn-block'>Add Education</button>
            </form>
            </div>
        </div>
    </div>
</div>
    )
  }
}
const mapStateToProps = (state) => (
    {
        errors: state.errors
    }
)
export default connect(mapStateToProps, { addEducation })(withRouter(AddEducation));