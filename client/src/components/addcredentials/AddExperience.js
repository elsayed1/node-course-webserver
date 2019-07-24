import React, { Component } from 'react';
import { withRouter } from 'react-router-dom';
import { connect } from 'react-redux';
import TextFieldGroup  from '../common/TextFieldGroup';
import TextAreaFieldGroup  from '../common/TextAreaFieldGroup';
import { addExperience } from '../../actions/profileActions';

class AddExperience extends Component {
    constructor(props){
        super(props);
        this.state = {
            title: '',
            company: '',
            location: '',
            from: '',
            to:   '',
            description: '',
            current: false,
            disabled: false,
            errors: {}
        }
    }
    componentWillReceiveProps(nextProps){
        if(nextProps.errors)
            this.setState({
                errors: nextProps.errors
        });
    }
    change = (e) => {
        this.setState({
            [e.target.name]: e.target.value
        })
    }
    checked = (e) => {
        this.setState({
            current: !this.state.current,
            disabled: !this.state.disabled
        })
    }
    submit = (e) => {
        e.preventDefault();
        this.props.addExperience(this.state, this.props.history);
    }
  render() {
    const state = this.state;
    console.log(state);
    return (
    <div className='addexperience'>
        <div className='container'>
            <div className="row">
            <div className='col-md-12 m-auto'>
            <p className="lead text-center">
                Enter any job or position you take it in the past or current
            </p>
            <form 
            className='custom-form'
            onSubmit={this.submit}
            
            >
                <h2 className='text-center'>Add Experience</h2>
                <hr/>
                <TextFieldGroup
                label='Title: '
                type='text'
                errors={state.errors}
                id='title_id'
                name='title'
                placeholder='Enter Title'
                value={state.title}
                onchange={this.change}
                />
                <TextFieldGroup
                label='Company: '
                type='text'
                errors={state.errors}
                id='company_id'
                name='company'
                placeholder='Enter Company'
                value={state.company}
                onchange={this.change}
                />
                <TextFieldGroup
                label='Start Date: '
                type='date'
                errors={state.errors}
                id='from_id'
                name='from'
                placeholder='Enter Start Date'
                value={state.from}
                onchange={this.change}
                />
                <TextFieldGroup
                label='End Date: '
                type='date'
                errors={state.errors}
                id='to_id'
                name='to'
                placeholder='Enter End Date'
                value={state.to}
                onchange={this.change}
                disabled={state.disabled?'disabled':''}
                />
                <div className='form-check mb-4 col-md-8 m-auto'>
                    <input 
                    type='checkbox'
                    name='current'
                    className='form-check-input'
                    defaultValue={state.current?'current':''}
                    checked={state.current}
                    onChange={this.checked}
                    />
                    <label htmlFor='current' className="form-check-label ml-3">
                        Current Job
                    </label>
                </div>
                <TextFieldGroup
                label='Location: '
                type='text'
                errors={state.errors}
                id='location_id'
                name='location'
                placeholder='Enter Location'
                value={state.location}
                onchange={this.change}
                />
                <TextAreaFieldGroup
                errors={state.errors}
                id='desc_id'
                name='description'
                placeholder='Enter Description'
                value={state.description}
                />
            <button type='submit' className='btn btn-success btn-block'>Add Experience</button>
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
export default  connect(mapStateToProps, { addExperience })(withRouter(AddExperience));
